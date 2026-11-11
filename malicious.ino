
#include <WiFi.h>
#include <HTTPClient.h>

//wi-Fi settings
const char* ssid = "Wokwi-GUEST";
const char* password = "";

//normal HTTP destination
const char* serverURL = "http://httpbin.org/get";

//suspicious HTTP destinations
const char* destinations[] = {
  "http://httpbin.org/get",
  "http://neverssl.com/online"
};

//host for unusual port connection attempts
const char* portTestHost = "example.com";

//timing settings
unsigned long previousTime = 0;
const unsigned long interval = 10000; // 10 seconds

unsigned long previousSuspiciousTime = 0;
const unsigned long suspiciousInterval = 60000; // 60 seconds


//setup
void setup() {
  Serial.begin(115200);

  //Wokwi Wi-Fi official setup
  Serial.print("Connecting to WiFi");

  WiFi.begin("Wokwi-GUEST", "", 6);

  while (WiFi.status() != WL_CONNECTED) {
    delay(100);
    Serial.print(".");
  }

  Serial.println(" Connected!");

  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());

  randomSeed(millis());

  Serial.println("\nDevice started.");
}


//normal behavior
void sendTemperatureUpdate() {

  //simulate temp reading
  float temperature = random(200, 300) / 10.0;

  Serial.println("\n--- Temperature Update ---");

  Serial.print("Temperature: ");
  Serial.print(temperature);
  Serial.println(" C");

  //send HTTP request
  if (WiFi.status() == WL_CONNECTED) {

    WiFiClient client;
    HTTPClient http;

    String url = String(serverURL) +
                 "?temperature=" + String(temperature, 1);

    http.begin(client, url);

    int responseCode = http.GET();

    Serial.print("HTTP Response: ");
    Serial.println(responseCode);

    http.end();

  } else {
    Serial.println("WiFi disconnected!");
  }
}


//suspicious request burst
void generateHTTPRequestBurst() {

  Serial.println("\n--- STARTING REQUEST BURST ---");

  for (int i = 0; i < 10; i++) {

    //alternate between destinations
    const char* currentURL = destinations[i % 2];

    WiFiClient client;
    HTTPClient http;

    Serial.print("Sending suspicious request #");
    Serial.println(i + 1);

    http.begin(client, currentURL);

    int responseCode = http.GET();

    Serial.print("HTTP Response: ");
    Serial.println(responseCode);

    http.end();

    delay(500);
  }

  Serial.println("--- REQUEST BURST COMPLETE ---");
}

//suspicious tcp connections
void generateSuspiciousPortActivity() {

  Serial.println("\n--- TESTING UNUSUAL PORTS ---");

  int ports[] = {23, 2222, 8080};

  for (int i = 0; i < 3; i++) {

    WiFiClient testClient;

    Serial.print("Attempting connection to ");
    Serial.print(portTestHost);
    Serial.print(":");
    Serial.println(ports[i]);

    //attempt connection with a 5 second timeout
    if (testClient.connect(portTestHost, ports[i], 5000)) {

      Serial.println("Connection established!");

      testClient.stop();

    } else {

      Serial.println("Connection failed or refused.");
    }

    delay(500);
  }

  Serial.println("--- PORT TESTING COMPLETE ---");
}

//combined suspicious behaviors
void generateSuspiciousActivity() {

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi disconnected! Skipping suspicious activity.");
    return;
  }

  Serial.println("\n================================");
  Serial.println("SIMULATING COMPROMISED DEVICE");
  Serial.println("================================");

  generateHTTPRequestBurst();

  generateSuspiciousPortActivity();

  Serial.println("\n--- SUSPICIOUS ACTIVITY COMPLETE ---");
}

//main loop
void loop() {

  unsigned long currentTime = millis();

  //normal temp update every 10 seconds
  if (currentTime - previousTime >= interval) {

    previousTime = currentTime;

    sendTemperatureUpdate();
  }

  //suspicious activity every 60 seconds
  if (currentTime - previousSuspiciousTime >= suspiciousInterval) {

    previousSuspiciousTime = currentTime;

    generateSuspiciousActivity();
  }
}