

## Quick start

### Configuration 
This service is configured using environment variables using [github.com/kelseyhightower/envconfig](https://github.com/kelseyhightower/envconfig) 
Envconfig supports the use of struct tags to specify alternate, default, and required environment variables.

Given the following config struct
```go
	var cfg struct {
		Env  string `default:"dev" envconfig:"ENV"`
		Service struct {
			Name            string        `default:"web-api" envconfig:"SERVICE_NAME"`
        },
    }

    envPrefix := "WEB_API"
	if err := envconfig.Process(envPrefix, &cfg); err != nil {
		log.Fatalf("main : Parsing Config : %+v", err)
	}
```


Envconfig will process value for `cfg.Env` by first trying to populate it with the value for `WEB_API_ENV`. If `WEB_API_ENV` 
is not set, it will then check for `ENV`. If envconfig can't find an environment variable value for either key, it will 
populate it with "dev" as the default value. 

`cfg.Service.Name` will be populated by checking for the environment variable using the following using `WEB_API_SERVICE_NAME`. 
 If that is not set, it will then check `SERVICE_NAME` or set the default value to "web-api".


### Building 

This service uses a multi-stage [Dockerfile](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/examples/aws-ecs-go-web-api/Dockerfile).
Since most projects will have additional packages that are contained in a parent directory from the service itself, the 
service must be built from the project root directory and reference the Dockerfile for the target service.  

```bash
docker build -f examples/aws-ecs-go-web-api/Dockerfile .
```

### Hot reloads 
When using docker-compose to run the services, it's a pain to manually stop/start the service to see your code changes. 
This service using a multi-stage docker build and uses [github.com/gravityblast/fresh](https://github.com/gravityblast/fresh) 
as the entrypoint for the target layer `dev`. The `docker-compose.yaml` config file references layer with `target: dev` 
and mounts the source code for the project as a volume. Fresh with then monitor your code base and (re)starts your 
service everytime you save a Go or template file. 

Fresh using the configuration file [fresh-auto-reload.conf](https://gitlab.com/geeks-accelerator/oss/devops/blob/master/fresh-auto-reload.conf)
