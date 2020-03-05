package dkron

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/expvar"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/serf/serf"
	"github.com/segmentio/ksuid"
	"github.com/sirupsen/logrus"
	status "google.golang.org/grpc/status"
)

const (
	pretty = "pretty"
)

// Transport is the interface that wraps the ServeHTTP method.
type Transport interface {
	ServeHTTP()
}

// HTTPTransport stores pointers to an agent and a gin Engine.
type HTTPTransport struct {
	Engine *gin.Engine

	agent *Agent
}

// NewTransport creates an HTTPTransport with a bound agent.
func NewTransport(a *Agent) *HTTPTransport {
	return &HTTPTransport{
		agent: a,
	}
}

func (h *HTTPTransport) ServeHTTP() {
	h.Engine = gin.Default()
	h.Engine.HTMLRender = CreateMyRender()
	rootPath := h.Engine.Group("/")

	rootPath.Use(h.HuamiSSOMiddleware())

	h.APIRoutes(rootPath)
	h.agent.DashboardRoutes(rootPath)

	h.Engine.Use(h.MetaMiddleware())

	log.WithFields(logrus.Fields{
		"address": h.agent.config.HTTPAddr,
	}).Info("api: Running HTTP server")

	go h.Engine.Run(h.agent.config.HTTPAddr)
}

// APIRoutes registers the api routes on the gin RouterGroup.
func (h *HTTPTransport) APIRoutes(r *gin.RouterGroup, middleware ...gin.HandlerFunc) {
	r.GET("/debug/vars", expvar.Handler())

	h.Engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	r.GET("/v1", h.indexHandler)
	v1 := r.Group("/v1")
	v1.Use(middleware...)
	v1.GET("/", h.indexHandler)
	v1.GET("/members", h.membersHandler)
	v1.GET("/leader", h.leaderHandler)
	v1.POST("/leave", h.leaveHandler)

	v1.POST("/jobs", h.jobCreateOrUpdateHandler)
	v1.PATCH("/jobs", h.jobCreateOrUpdateHandler)
	// Place fallback routes last
	v1.GET("/jobs", h.jobsHandler)

	jobs := v1.Group("/jobs")
	jobs.DELETE("/:job", h.jobDeleteHandler)
	jobs.POST("/:job", h.jobRunHandler)
	jobs.POST("/:job/toggle", h.jobToggleHandler)

	// Place fallback routes last
	jobs.GET("/:job", h.jobGetHandler)
	jobs.GET("/:job/executions", h.executionsHandler)
}

// MetaMiddleware adds middleware to the gin Context.
func (h *HTTPTransport) MetaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Whom", h.agent.config.NodeName)
		c.Next()
	}
}

// HuamiSSOMiddleware adds middleware to the gin Context.
func (h *HTTPTransport) HuamiSSOMiddleware() gin.HandlerFunc {
	jwtName := "dkron_jwt"
	signName := "HS256"
	secret := []byte("HUAMI SSO")
	return func(c *gin.Context) {
		redirectURL := h.agent.config.HuamiSSO + "?admin_public_callback_url=" + c.Request.Host
		cookieDomain := c.Request.Host
		if strings.Contains(cookieDomain, ":") {
			cookieDomain = strings.Split(cookieDomain, ":")[0]
		}
		// get jwt from cookie
		jwtStr, err := c.Cookie(jwtName)
		if err != nil {
			// get apptoken from cookie
			apptoken, err := c.Cookie("apptoken")
			log.WithFields(logrus.Fields{
				"apptoken": apptoken,
				"error":    err,
			}).Info("api: apptoken from cookie")
			if err != nil {
				// no app token, login huami sso
				c.Redirect(http.StatusTemporaryRedirect, redirectURL)
				c.Abort()
				return
			}
			// verify apptoken and get user info
			user, err := verifyHMToken(h.agent.config.HuamiTokenVerify, apptoken)
			log.WithFields(logrus.Fields{
				"user":  user,
				"error": err,
			}).Info("api: verify app token")
			if err != nil {
				// verify error, login huami sso
				c.Redirect(http.StatusTemporaryRedirect, redirectURL)
				c.Abort()
				return
			}
			// Create the token
			token := jwt.New(jwt.GetSigningMethod(signName))
			claims := token.Claims.(jwt.MapClaims)
			claims["id"] = user.UserID
			claims["email"] = user.Email
			expire := time.Now().Add(time.Hour)
			claims["exp"] = expire.Unix()
			claims["orig_iat"] = time.Now().Unix()
			tokenString, err := token.SignedString(secret)
			if err != nil {
				log.WithFields(logrus.Fields{
					"error": err,
				}).Error("api: sign token error")
				c.Abort()
				return
			}
			maxage := int(expire.Unix() - time.Now().Unix())
			fmt.Println("jwt", tokenString)

			// set jwt cookie
			c.SetCookie(jwtName, tokenString, maxage, "/", cookieDomain, false, true)
			c.Redirect(http.StatusTemporaryRedirect, "/"+dashboardPathPrefix+"/")
			c.Abort()
			return
		}

		token, err := jwt.Parse(jwtStr, func(t *jwt.Token) (interface{}, error) {
			if jwt.GetSigningMethod(signName) != t.Method {
				return nil, errors.New("method error")
			}
			return secret, nil
		})
		log.WithFields(logrus.Fields{
			"jwt":   jwtStr,
			"token": token,
			"error": err,
		}).Info("api: verify jwt token")

		if err != nil {
			// verify error, login huami sso
			c.SetCookie(jwtName, "", -1, "/", cookieDomain, false, true)
			c.Redirect(http.StatusTemporaryRedirect, redirectURL)
			c.Abort()
			return
		}
		if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
			var user hmUser
			if id, ok := mapClaims["id"]; ok {
				user.UserID = id.(string)
			}
			if email, ok := mapClaims["email"]; ok {
				user.Email = email.(string)
			}
			c.Set("HMUser", user)
		}

		c.Next()
	}
}

func renderJSON(c *gin.Context, status int, v interface{}) {
	if _, ok := c.GetQuery(pretty); ok {
		c.IndentedJSON(status, v)
	} else {
		c.JSON(status, v)
	}
}

func (h *HTTPTransport) indexHandler(c *gin.Context) {
	local := h.agent.serf.LocalMember()

	stats := map[string]map[string]string{
		"agent": {
			"name":    local.Name,
			"version": Version,
		},
		"serf": h.agent.serf.Stats(),
		"tags": local.Tags,
	}

	renderJSON(c, http.StatusOK, stats)
}

func (h *HTTPTransport) jobsHandler(c *gin.Context) {
	metadata := c.QueryMap("metadata")

	jobs, err := h.agent.Store.GetJobs(
		&JobOptions{
			Metadata: metadata,
		},
	)
	if err != nil {
		log.WithError(err).Error("api: Unable to get jobs, store not reachable.")
		return
	}
	renderJSON(c, http.StatusOK, jobs)
}

func (h *HTTPTransport) jobGetHandler(c *gin.Context) {
	jobName := c.Param("job")

	job, err := h.agent.Store.GetJob(jobName, nil)
	if err != nil {
		log.Error(err)
	}
	if job == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	renderJSON(c, http.StatusOK, job)
}

func (h *HTTPTransport) jobCreateOrUpdateHandler(c *gin.Context) {
	// Init the Job object with defaults
	var user hmUser
	if u, ok := c.Get("HMUser"); ok {
		user = u.(hmUser)
	}
	job := Job{
		Concurrency: ConcurrencyAllow,
		Tags:        map[string]string{"role": "dkron:1"},
		Owner:       user.UserID,
		OwnerEmail:  user.Email,
	}

	// Parse values from JSON
	if err := c.BindJSON(&job); err != nil {
		c.Writer.WriteString(fmt.Sprintf("Unable to parse payload: %s.", err))
		log.Error(err)
		return
	}
	if job.Name == "" {
		// create job with new name
		job.Name = ksuid.New().String()[:10]
	}

	// Validate job
	if err := job.Validate(); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		c.Writer.WriteString(fmt.Sprintf("Job contains invalid value: %s.", err))
		return
	}

	// Call gRPC SetJob
	if err := h.agent.GRPCClient.SetJob(&job); err != nil {
		s := status.Convert(err)
		if s.Message() == ErrParentJobNotFound.Error() {
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		c.Writer.WriteString(s.Message())
		return
	}

	// Immediately run the job if so requested
	if _, exists := c.GetQuery("runoncreate"); exists {
		h.agent.GRPCClient.RunJob(job.Name)
	}

	c.Header("Location", fmt.Sprintf("%s/%s", c.Request.RequestURI, job.Name))
	renderJSON(c, http.StatusCreated, &job)
}

func (h *HTTPTransport) jobDeleteHandler(c *gin.Context) {
	jobName := c.Param("job")

	// Call gRPC DeleteJob
	job, err := h.agent.GRPCClient.DeleteJob(jobName)
	if err != nil {
		c.AbortWithError(http.StatusNotFound, err)
		return
	}
	renderJSON(c, http.StatusOK, job)
}

func (h *HTTPTransport) jobRunHandler(c *gin.Context) {
	jobName := c.Param("job")

	// Call gRPC RunJob
	job, err := h.agent.GRPCClient.RunJob(jobName)
	if err != nil {
		c.AbortWithError(http.StatusNotFound, err)
		return
	}

	c.Header("Location", c.Request.RequestURI)
	c.Status(http.StatusAccepted)
	renderJSON(c, http.StatusOK, job)
}

func (h *HTTPTransport) executionsHandler(c *gin.Context) {
	jobName := c.Param("job")

	job, err := h.agent.Store.GetJob(jobName, nil)
	if err != nil {
		c.AbortWithError(http.StatusNotFound, err)
		return
	}

	executions, err := h.agent.Store.GetExecutions(job.Name)
	if err != nil {
		if err == badger.ErrKeyNotFound {
			renderJSON(c, http.StatusOK, &[]Execution{})
			return
		}
		log.Error(err)
		return

	}
	renderJSON(c, http.StatusOK, executions)
}

func (h *HTTPTransport) membersHandler(c *gin.Context) {

	numbers := make([]serf.Member, 0)
	for _, number := range h.agent.serf.Members() {
		if number.Status == serf.StatusAlive {
			numbers = append(numbers, number)
		}
	}
	sort.SliceStable(numbers, func(i, j int) bool {
		return numbers[i].Name < numbers[j].Name
	})

	renderJSON(c, http.StatusOK, h.agent.serf.Members())
}

func (h *HTTPTransport) leaderHandler(c *gin.Context) {
	member, err := h.agent.leaderMember()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}
	if member == nil {
		c.AbortWithStatus(http.StatusNotFound)
	}
	renderJSON(c, http.StatusOK, member)
}

func (h *HTTPTransport) leaveHandler(c *gin.Context) {
	if err := h.agent.Stop(); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}
	renderJSON(c, http.StatusOK, h.agent.peers)
}

func (h *HTTPTransport) jobToggleHandler(c *gin.Context) {
	jobName := c.Param("job")

	job, err := h.agent.Store.GetJob(jobName, nil)
	if err != nil {
		c.AbortWithError(http.StatusNotFound, err)
		return
	}

	// Toggle job status
	job.Disabled = !job.Disabled

	// Call gRPC SetJob
	if err := h.agent.GRPCClient.SetJob(job); err != nil {
		c.AbortWithError(http.StatusUnprocessableEntity, err)
		return
	}

	c.Header("Location", c.Request.RequestURI)
	renderJSON(c, http.StatusOK, job)
}
