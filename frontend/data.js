// Datos del frontend. Con backend, los ataques llegan por WebSocket; SOURCES y
// CREDENTIALS solo se usan en la simulación local (cuando no hay backend).

// Red de honeypots. El id es el campo "sensor" que escribe Cowrie en cada evento
// (en cowrie.cfg: [honeypot] sensor_name = fra-01). Añade aquí los tuyos.
const SENSORS = [
  { id: "fra-01", city: "Frankfurt", lat: 50.11, lng: 8.68 },
  { id: "nyc-01", city: "Nueva York", lat: 40.71, lng: -74.01 },
  { id: "sao-01", city: "São Paulo", lat: -23.55, lng: -46.63 },
  { id: "sgp-01", city: "Singapur", lat: 1.35, lng: 103.82 },
  { id: "syd-01", city: "Sídney", lat: -33.87, lng: 151.21 },
  { id: "jnb-01", city: "Johannesburgo", lat: -26.2, lng: 28.05 },
  { id: "tyo-01", city: "Tokio", lat: 35.68, lng: 139.69 },
];

// Países de origen para la simulación local (peso = frecuencia relativa).
const SOURCES = [
  { country: "China", code: "CN", lat: 35.9, lng: 104.2, w: 18 },
  { country: "Rusia", code: "RU", lat: 61.5, lng: 105.3, w: 14 },
  { country: "Estados Unidos", code: "US", lat: 39.8, lng: -98.6, w: 12 },
  { country: "Brasil", code: "BR", lat: -14.2, lng: -51.9, w: 8 },
  { country: "India", code: "IN", lat: 20.6, lng: 78.9, w: 8 },
  { country: "Vietnam", code: "VN", lat: 14.1, lng: 108.3, w: 6 },
  { country: "Irán", code: "IR", lat: 32.4, lng: 53.7, w: 5 },
  { country: "Indonesia", code: "ID", lat: -0.8, lng: 113.9, w: 5 },
  { country: "Corea del Sur", code: "KR", lat: 35.9, lng: 127.8, w: 4 },
  { country: "Ucrania", code: "UA", lat: 48.4, lng: 31.2, w: 4 },
  { country: "México", code: "MX", lat: 23.6, lng: -102.5, w: 3 },
  { country: "Colombia", code: "CO", lat: 4.6, lng: -74.1, w: 3 },
  { country: "Turquía", code: "TR", lat: 38.9, lng: 35.2, w: 3 },
  { country: "Nigeria", code: "NG", lat: 9.1, lng: 8.7, w: 2 },
  { country: "Sudáfrica", code: "ZA", lat: -30.6, lng: 22.9, w: 2 },
  { country: "Alemania", code: "DE", lat: 51.2, lng: 10.4, w: 2 },
];

// Tipos de ataque con color. Los ids coinciden con backend/app/classify.py.
const ATTACK_TYPES = [
  { id: "ssh-brute", label: "Fuerza bruta SSH", color: "#ff4d6d", w: 40 },
  { id: "scan", label: "Escaneo", color: "#ffd166", w: 30 },
  { id: "intrusion", label: "Acceso concedido", color: "#ff8c42", w: 8 },
  { id: "command", label: "Comandos en shell", color: "#36e6c1", w: 12 },
  { id: "malware", label: "Descarga de malware", color: "#b388ff", w: 6 },
  { id: "botnet", label: "Botnet / Mirai", color: "#4dabf7", w: 4 },
];

// Credenciales genéricas típicas de ataques automatizados (solo datos de ejemplo).
const CREDENTIALS = [
  "root:123456", "admin:admin", "root:password", "ubuntu:ubuntu",
  "user:1234", "test:test", "pi:raspberry", "root:toor",
  "admin:12345", "oracle:oracle", "postgres:postgres", "root:root",
];
