package api

const (
	RESOURCE_BOOKS       = "books"
	ENDPOINT_BOOKS       = "/" + RESOURCE_BOOKS
	ENDPOINT_BOOKS_BY_ID = "/" + RESOURCE_BOOKS + "/:bookId"

	RESOURCE_AUTH        = "auth"
	ENDPOINT_AUTH_LOGIN  = "/" + RESOURCE_AUTH + "/login"
	ENDPOINT_AUTH_LOGOUT = "/" + RESOURCE_AUTH + "/logout"
	ENDPOINT_AUTH_TOKEN  = "/" + RESOURCE_AUTH + "/token"

	ENDPOINT_HEALTH  = "/health"
	ENDPOINT_METRICS = "/metrics"
	ENDPOINT_SWAGGER = "/swagger"
)
