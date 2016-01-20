#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include <jansson.h>

#include <jwt.h>

struct jwt {
        jwt_alg_t alg;
        unsigned char *key;
        int key_len;
        json_t *grants;
};

struct userdata {
        char *username;
};


int mosquitto_auth_plugin_version(void) {
  return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {

   *user_data = (struct userdata *)malloc(sizeof(struct userdata));
   if (*user_data == NULL) {
     perror("allocting userdata");
     return MOSQ_ERR_UNKNOWN;
  }
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
  
  	struct userdata *ud = (struct userdata *)user_data; 
  	jwt_t *jwt;
  	const char* val;
  	int i_val;
  	time_t now;
  	int iat;
  	int exp;

	//TODO put all these constants in the plugin parameters
  	unsigned char key[32] = "012345678901234567890123456789AB";
  	const char producer_login[9] = "producer";
	const char producer_pwd[17] = "b7bc7Bx7QDDATVdk";

  	if (username == NULL || password == NULL) {
    	   return MOSQ_ERR_AUTH;
  	}

#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_unpwd_check: username=%s, password=%s\n", username, password);
#endif

	// producer account, in my case the only one that can publish
	if ( ! strcmp(username, producer_login) && ! strcmp(password, producer_pwd) ) {
#ifdef MQAP_DEBUG
  	  fprintf(stderr, "mosquitto_auth_unpwd_check: producer is allowed to connect \n");
#endif
       	  return MOSQ_ERR_SUCCESS;
	}
	

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
          val = jwt_get_grant(jwt, "sub");
	  ud->username = (char *)malloc(sizeof(char)*strlen(val));
          strcpy(ud->username, val);
	  //TODO add the username <-> allowed topic to a hashtable

          fprintf(stderr, "mosquitto_auth_unpwd_check:  sub : %s\n", val); 

	  jwt_free(jwt);
       	  return MOSQ_ERR_SUCCESS;
        } else {
#ifdef MQAP_DEBUG
	  fprintf(stderr, "mosquitto_auth_unpwd_check:  password is not a valid token %d\n", status);
#endif	
        }

  	return MOSQ_ERR_AUTH;
}

// Check if  part1 + part2 == to_compare
// returns 0 if no difference, 1 otherwise
int strmcmp(const char* part1, const char* part2, const char* to_compare) {

  int len1 = strlen(part1);
  int len2 = strlen(part2);
  int len  = strlen(to_compare);
  int i;

  if ( len1 + len2 != len ) {
        return 1;
  } else {

        for (i=0; i<len; i++) {
                if ( i < len1 ) {
                        if ( part1[i] != to_compare[i] ) {
                                return 1;
                        }
                } else if (part2[i-len1] != to_compare[i] ) {
                        return 1;
                }
        }
  }

  return 0;
}



int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {

const char producer_login[9] = "producer";
const char root_topic[10] = "CLE/DEMO/";

  char access_name[6];
  if (access == 0) {
    sprintf(access_name, "none");
  } else if (access == 1) {
    sprintf(access_name, "read");
  } else if (access == 2) {
    sprintf(access_name, "write");
  }


#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_acl_check: clientid=%s, username=%s, topic=%s, access=%s\n", clientid, username, topic, access_name);
#endif

  if ( username == NULL ) {
#ifdef MQAP_DEBUG
   fprintf(stderr, "mosquitto_auth_acl_check: anonymous user is not allowed\n");
#endif
   return MOSQ_ERR_ACL_DENIED;

  }

  if ( ! strcmp(username, producer_login) && (access == 2) ) {
#ifdef MQAP_DEBUG
	fprintf(stderr, "mosquitto_auth_acl_check: user %s is allowed to write\n", username);
#endif
	return MOSQ_ERR_SUCCESS;
  }
 
  if ( ! strmcmp( root_topic, username, topic ) && (access == 1) )  {
#ifdef MQAP_DEBUG
	fprintf(stderr, "mosquitto_auth_acl_check: user %s is allowed to read on topic %s\n", username, topic);
#endif
  	return MOSQ_ERR_SUCCESS;
  }

#ifdef MQAP_DEBUG
  fprintf(stderr, "mosquitto_auth_acl_check: user %s is not allowed\n", username);
#endif
  return MOSQ_ERR_ACL_DENIED;
}


int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len) {
  return MOSQ_ERR_AUTH;
}

