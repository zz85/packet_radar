use maxminddb::{MaxMindDBError, Reader};
use maxminddb::geoip2::{City, Asn};

use std::net::IpAddr;
use std::str::FromStr;

use maxminddb;

pub fn geo_lookup() {
    let filename = "geodata/mmdb/GeoLite2-City.mmdb";
    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("1.1.1.1").unwrap();
    // 89.160.20.112
    let city: City = reader.lookup(ip).unwrap();
    println!("City {:?}", city);

    // city.location.latitude/longitude/time_zone
    // city.names.en
    // city.country.iso_code
    let iso_code = city.country.and_then(|cy| cy.iso_code);
    
    asn_lookip();
}

pub fn asn_lookip() {
    let filename = "geodata/mmdb/GeoLite2-ASN.mmdb";
    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("1.1.1.1").unwrap();
    // 89.160.20.112
    let asn: Asn = reader.lookup(ip).unwrap();
    // autonomous_system_number
    // autonomous_system_organization
    println!("asn {:?}", asn);
}