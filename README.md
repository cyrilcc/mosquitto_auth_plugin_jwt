# mosquitto_auth_plugin_jwt
JWT Auth Plugin for Mosquitto 

This is a plugin to authenticate and authorize [Mosquitto] users with a [JWT](https://jwt.io/) token obtained from an authentication server.

This has been done for a study purpose, feel free to adapt for your usage.

### Configuration 
```
auth_plugin /path/to/mosquitto_auth_plugin_jwt.so
```

### Dependencies
* [libjwt](https://github.com/benmcollins/libjwt)
* [Mosquitto]
