# Google Cloud Platform Api Gateway

## What is API Gateway?

As per the [documentation](https://cloud.google.com/api-gateway), _Api gateway is a fully mangaged gateway for serverless workloads._ 

So really at the end of the day, that boils down to a serverless gateway for you serverless api's... Man that's alot of serverless.

## What does API Gateway do?

API gateway will act as the middleman between an end user and your services. You describe your services according to the OpenAPI specification, 
upload the specification to api gateway center and then finally deploy the spec to a gateway. API Gateway also provides a suite of utilities, such as monitoring, logging and authentication.

## When should I use API Gateway?

If you are going to be using the Serverless GCP eco-system(Cloud Functions, Cloud Run, App Engine), then API Gateway will be complimentary to those serverless products.  

## Why should I use API Gateway?

The most important question to answer is "why", why should I use API Gateway?

Security - Your core application can be deployed and protected by GCP IAM, that way the only direct interactions with your services will be done with the api gateway.

Externalized Configuration - You have an external way to manage application authentication, service url mapping, and API documentation that lives outside the context of the application. 

Less Code - Your application itself won't have to worry about validating JWT/Api Keys since those will be handled at the gateway layer, and the result will be forwarded to your application. The less code you write, the fewer bugs there will be 😬

Observability - All your performance metrics will roll up to a single, easy to view dashboard with all your KPI's such as request latency, error rates, requests per second and more.

## Securing Cloud Run Services with Firebase Authentication. 

First we will take a look at our openapi specification file to get an understanding of our api. It is pretty straight forward, a single endpoint named `/greet` that will echo back the users name but in a "greeted" format.

`openapi2-run.yaml`
```yaml
swagger: '2.0'
info:
  # Title of the api gateway
  title: gateway
  description: Sample API on API Gateway with a Cloud Run backend
  version: 1.0.0
schemes:
  - https
produces:
  - application/json
# The cloud run service url, this could also be defined per path as well in case you have multiple cloud run services that
# make up a single gateway
x-google-backend:
  address: "YOUR-CLOUD_RUN-URL"
securityDefinitions:
  firebase:
    authorizationUrl: ""
    flow: "implicit"
    type: "oauth2"
    # Replace YOUR-PROJECT-ID with your project ID
    x-google-issuer: "https://securetoken.google.com/YOUR-PROJECT-ID"
    x-google-jwks_uri: "https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com"
    x-google-audiences: "YOUR-PROJECT-ID"
paths:
  /greet:
    get:
      summary: Greets the user
      operationId: greet
      # define that our service uses the firebase security definition
      security:
        - firebase: [ ]
      responses:
        '200':
          description: A successful response
          schema:
            type: object
            # our object look like `{name: ""}`
            properties:
              name:
                type: string
                description: The users name
```

Now we will take a peek at the code that will fulfill the contract of the api.

`cmd/routes.go`
```go
func (s *server) routes() {
	s.router.HandleFunc("/greet", s.handleAuth(s.handleGreeting()))
}

//handleGreeting will fetch the UserInfo struct that is stored in context from our auth middleware and use that to greet the person that called our api
func (s *server) handleGreeting() http.HandlerFunc {

	type person struct {
		Name string `json:"name"`
	}

	return func(writer http.ResponseWriter, request *http.Request) {

		writer.Header().Set("Content-Type", "application/json")

		// fetch the token user object that is stored in context
		userObj := request.Context().Value(gatewayUserContext).(UserInfo)

		// greet the user 👋
		p := person{Name: fmt.Sprintf("Hello 👋 %s", userObj.Name)}
		decoder := json.NewEncoder(writer)

		if err := decoder.Encode(p); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	}
}
```


And just for a quick review of the Auth Middleware.

`cmd/auth.go`
```go
const gatewayUserInfoHeader = "X-Apigateway-Api-Userinfo"
const gatewayUserContext = "GATEWAY_USER"

type UserInfo struct {
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Iss           string   `json:"iss"`
	Aud           string   `json:"aud"`
	AuthTime      int      `json:"auth_time"`
	UserID        string   `json:"user_id"`
	Sub           string   `json:"sub"`
	Iat           int      `json:"iat"`
	Exp           int      `json:"exp"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Firebase      Firebase `json:"firebase"`
}
type Identities struct {
	GoogleCom []string `json:"google.com"`
	Email     []string `json:"email"`
}
type Firebase struct {
	Identities     Identities `json:"identities"`
	SignInProvider string     `json:"sign_in_provider"`
}

// handleAuth is a piece of middleware that will parse the gatewayUserInfoHeader from the request and add the UserInfo to the request context
func (s *server) handleAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		encodedUser := r.Header.Get(gatewayUserInfoHeader)
		if encodedUser == "" {
			http.Error(w, "User Not Available", http.StatusForbidden)
			return
		}
		decodedBytes, err := base64.RawURLEncoding.DecodeString(encodedUser)
		if err != nil {
			http.Error(w, "Invalid UserInfo", http.StatusForbidden)
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(decodedBytes))
		var userToken UserInfo
		err = decoder.Decode(&userToken)
		if err != nil {
			http.Error(w, "Invalid UserInfo", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), gatewayUserContext, userToken)
		h.ServeHTTP(w, r.WithContext(ctx))

	}
}
```

You can see the rest of the code for the application in the github repo.


### Enable API's and Create service account

Make sure you enable the following api's on your project

```
gcloud services enable apigateway.googleapis.com
gcloud services enable servicemanagement.googleapis.com
gcloud services enable servicecontrol.googleapis.com
```

Lets create our api gateway service account 

```
gcloud iam service-accounts create api-gateway

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID --member "serviceAccount:api-gateway@YOUR_PROJECT_ID.iam.gserviceaccount.com" --role "roles/run.invoker"
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID --member "serviceAccount:api-gateway@YOUR_PROJECT_ID.iam.gserviceaccount.com" --role "roles/iam.serviceAccountUser"
```


### Build and Deployment

Since we are going to be using cloud build to roll everthing out, lets get our container built and deployed with `gcloud builds submit`

`cloudbuild.yaml`
```yaml
steps:

  # Run the docker build
  - name: 'gcr.io/cloud-builders/docker'
    args: [ 'build', '-t', 'gcr.io/$PROJECT_ID/greeter', '.' ]

  # push the docker image to the private GCR registry
  - name: 'gcr.io/cloud-builders/docker'
    args: [ 'push', 'gcr.io/$PROJECT_ID/greeter' ]

  # deploy to cloud run
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args: [ 'run', 'deploy', 'greeter', '--image', 'gcr.io/$PROJECT_ID/greeter', '--region', 'us-central1', '--platform', 'managed', '--no-allow-unauthenticated' ]

images:
  - 'gcr.io/$PROJECT_ID/greeter'

```

Now that we have the cloud service deployed, we just need to get our cloud run url `gcloud run services describe greeter --format 'value(status.url)'`
and to verify its secure we can try to `curl` the endpoint `curl $(gcloud run services describe greeter --format 'value(status.url)')` and we should get a 403.

The next step is to take that url from our endpoint and plug it into our api spec as the address for the `x-google-backend`

```yaml
# The cloud run service url, this could also be defined per path as well in case you have multiple cloud run services that
# make up a single gateway
x-google-backend:
  address: "YOUR-CLOUD_RUN-URL"
```

Now we are turning to the home stretch, we just need to deploy our gateway/config

```

# create api config
gcloud beta api-gateway api-configs create echoconf \
  --api=gateway --openapi-spec=openapi2-run.yaml \
  --backend-auth-service-account=api-gateway@YOUR_PROJECT_ID.iam.gserviceaccount.com


# create gateway with config
gcloud beta api-gateway gateways create gateway \
  --api=gateway --api-config=echoconf \
  --location=us-central1


#get hostname from gateway
gcloud beta api-gateway gateways describe gateway \
  --location=us-central1 --format 'value(defaultHostname)'
```

Now if we `curl` the gateway endpoint with
```
curl "https://$(gcloud beta api-gateway gateways describe gateway --location=us-central1 --format 'value(defaultHostname)')/greet"
```

we will get a 401 since we didn't attach a firebase identity token to request.
 
 But once you attach the token to the request as either a query param of `access_token` or as an Authorization header with bearer token
```
curl "https://$(gcloud beta api-gateway gateways describe gateway --location=us-central1 --format 'value(defaultHostname)')/greet?access_token=ACCESS_TOKEN"
```
We will get back our greeted message! `{
                                         "name": "Hello 👋 Alex Mammay"
                                       }`


