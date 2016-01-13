#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include <jansson.h>

#include <jwt.h>

int mosquitto_auth_plugin_version(void) {
  return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

struct jwt {
	jwt_alg_t alg;
	unsigned char *key;
	int key_len;
	json_t *grants;
};


static int get_js_int(json_t *js, const char *key)
{
	int val = 0;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val)
		val = json_integer_value(js_val);

	return val;
}

static char *get_js_object(json_t *js, const char *key)
{
	size_t flags = JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY;
	char *val = NULL;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val)
		val = json_dumps(js_val, flags);

	return val;
}


int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password) {
  
  jwt_t *jwt;
#ifdef MQAP_DEBUG
  const char* val;
  int i_val;
#endif
  time_t now;
  int iat;
  int exp;
  unsigned char key[32] = "012345678901234567890123456789AB";

  if (username == NULL || password == NULL) {
    return MOSQ_ERR_AUTH;
  }
#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_unpwd_check: username=%s, password=%s\n", username, password);
#endif
  if ( ! strcmp(username, "jwt") ) {

	time(&now);

	int status = jwt_decode(&jwt, password, key , sizeof(key));

	if (( status == 0 ) && (jwt != NULL) ) {
#ifdef MQAP_DEBUG	
		fprintf(stderr, "mosquitto_auth_unpwd_check:  password is a valid JWT token\n");
		val = jwt_get_grant(jwt, "iss");
     		fprintf(stderr, "mosquitto_auth_unpwd_check:  iss : %s\n", val);
		val = jwt_get_grant(jwt, "sub");
     		fprintf(stderr, "mosquitto_auth_unpwd_check:  sub : %s\n", val);
		i_val = get_js_int(jwt->grants, "iat");
     		fprintf(stderr, "mosquitto_auth_unpwd_check:  iat : %d\n", i_val);
		i_val = get_js_int(jwt->grants, "exp");
     		fprintf(stderr, "mosquitto_auth_unpwd_check:  exp : %d\n", i_val);
		val = get_js_object(jwt->grants, "aud");
     		fprintf(stderr, "mosquitto_auth_unpwd_check:  aud : %s\n", val);
     		fprintf(stderr, "mosquitto_auth_unpwd_check:  now : %d\n", (int)now);
#endif
		iat = get_js_int(jwt->grants, "iat");		
		exp = get_js_int(jwt->grants, "exp");		
		if ( (now < iat) || (now > exp) ) {
#ifdef MQAP_DEBUG
                fprintf(stderr, "mosquitto_auth_unpwd_check:  token is expired\n");
#endif
		   jwt_free(jwt);
                   return MOSQ_ERR_AUTH;
		}

		// TODO add here some other controls about iss, sub, ...

		jwt_free(jwt);
        	return MOSQ_ERR_SUCCESS;
  	} else {
#ifdef MQAP_DEBUG
		fprintf(stderr, "mosquitto_auth_unpwd_check:  password is not a valid token %d\n", status);
#endif	
	}
  } 

  return MOSQ_ERR_AUTH;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {

  char access_name[6];
  if (access == 0) {
    sprintf(access_name, "none");
  } else if (access == 1) {
    sprintf(access_name, "read");
  } else if (access == 2) {
    sprintf(access_name, "write");
  }
#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_acl_check: clientid=%s, username=%s, topic=%s, access=%s\n",
    clientid, username, topic, access_name);
#endif
  //return (rc == 200 ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return MOSQ_ERR_AUTH;
}

