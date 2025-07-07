mod config;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::read_config();

    let cert = {
        let cert_path = Path::new(&config.send.cli_key_x509);
        X509::from_pem(&fs::read(cert_path)?)?
    };

    let key = {
        let key_path = Path::new(&config.send.cli_key_priv);
        PKey::private_key_from_pem(&fs::read(key_path)?)?
    };

    let ca = Path::new(&config.send.ca_x509);

    println!("Create connector...");
    let connector = {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_ca_file(ca)?;
        builder.set_certificate(&cert)?;
        builder.set_private_key(&key)?;
        builder.check_private_key()?;
        builder.build()
    };

    println!("Create ssl stream...");
    let mut ssl_stream = {
        let stream = TcpStream::connect(&format!(
            "{}:{}",
            config.send.server_name, config.send.server_port
        ))
        .unwrap();
        connector.connect(&config.send.server_name, stream)?
    };

    if config.send.server_cert_x509.len() > 0 {
        println!("Controle server certif...");
        let opt_serv_cert = ssl_stream.ssl().peer_certificate();
        let local_pub_cert = {
            let path = Path::new(&config.send.server_cert_x509);
            let x509 = X509::from_pem(&fs::read(path)?)?;
            x509.public_key()?
        };
        let Some(serv_cert) = opt_serv_cert else {
            return Err("No server certificat".into());
        };
        let srv_pub = serv_cert.public_key()?;
        if false == local_pub_cert.public_eq(&srv_pub) {
            return Err("Server key does not correspond".into());
        }
    }

    ssl_stream
        .write_all(format!("ME {}", config.send.save_name).as_bytes())
        .unwrap();

    let mut buf = [0; 1024];
    ssl_stream.read(&mut buf).unwrap();
    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
