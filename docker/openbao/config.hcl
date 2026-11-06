ui = true
disable_mlock = true

# OpenBao 2.7 removed the file storage backend. PebbleDB is the built-in,
# single-node durable backend that replaces it. The Credo agent's own data lives
# in SQLite; OpenBao has no SQLite storage backend.
storage "pebbledb" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = "true"
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"
