#include <WiFi.h>
#include <HTTPClient.h>

// Wi-Fi settings
const char* ssid = "Wokwi-GUEST";
const char* password = "";

// HTTP destination
const char* serverURL = "http://httpbin.org/get";

// Send an update every 10 seconds
unsigned long previousTime = 0;
const unsigned long interval = 10000;

void setup() {
  Serial.begin(115200);

  // Connect to Wokwi Wi-Fi (official example setup)
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
}

void loop() {
  // Send a temperature update every 10 seconds
  if (millis() - previousTime >= interval) {
    previousTime = millis();

    // Simulate temperature between 20.0 and 29.9 C
    float temperature = random(200, 300) / 10.0;

    Serial.println("\n--- Temperature Update ---");
    Serial.print("Temperature: ");
    Serial.print(temperature);
    Serial.println(" C");

    // Send HTTP request
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
}
