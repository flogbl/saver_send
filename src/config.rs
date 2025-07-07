use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub send: Send,
}
#[derive(Deserialize, Clone)]
pub struct Send {
    pub save_name: String,
    pub cli_key_x509: String,
    pub cli_key_priv: String,
    pub server_cert_x509: String,
    pub server_name: String,
    pub server_port: String,
    pub ca_x509: String,
}
pub fn read_config() -> Config {
    let content = match std::fs::read_to_string(".saver.toml") {
        Ok(c) => c,
        Err(e) => panic!("Can't access config file. Error : {e}"),
    };
    toml::from_str(&content).unwrap()
}
