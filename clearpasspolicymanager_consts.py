# CPPM Constants

CCPM_JSON_BASE_URL = "base_url"
CPPM_JSON_CLIENT_ID = "client_id"
CPPM_JSON_CLIENT_SECRET = "client_secret"
CCPM_OAUTH_TOKEN = 'access_token'

# Messages
CPPM_ERR_CONNECTIVITY_TEST = "Test connectivity failed"
CPPM_SUCC_CONNECTIVITY_TEST = "Test connectivity passed"
CPPM_ERR_TERMINATE_SESSION_QUERY_SESSIONS = "Could not query sessions for device"
CPPM_ERR_TERMINATE_SESSION_DISCONNECT_SESSION = "Could not disconnect session"
CPPM_ERR_ATTRIBUTES_JSON_PARSE = "Could not parse attributes json"
CPPM_ERR_GET_ENDPOINT = "Could not retrieve endpoint information"
CPPM_SUCC_GET_ENDPOINT = "Successfully retrieved endpoint by mac"
CPPM_SUCC_UPDATE_ENDPOINT = "Successfully updated endpoint by mac"
CPPM_ERR_UPDATE_ENDPOINT = "Could not update endpoint by mac"
CPPM_ERR_GET_DEVICE = "Could not retrieve device information"
CPPM_SUCC_GET_DEVICE = "Successfully retrieved device by mac"
CPPM_ERR_GET_GUESTUSER = "Could not retrieve guest user information"
CPPM_SUCC_GET_GUESTUSER = "Successfully retrieved guest user Information"

# Auth
CPPM_OAUTH_TOKEN_ENDPOINT = "/api/oauth"
CPPM_OAUTH_ME_ENDPOINT = "/api/oauth/me"

# Sessions
CPPM_SESSIONS_ENDPOINT = "/api/session"
CPPM_DISCONNECT_SESSION_ENDPOINT = "/api/session/{0}/disconnect"

# Endpoints
CPPM_ENDPOINT_MAC_ENDPOINT = "/api/endpoint/mac-address/{0}"
CPPM_DEVICE_MAC_ENDPOINT = "/api/device/mac/{0}"
CPPM_GUEST_USER_ENDPOINT = "/api/guest/username/{0}"
