use maxminddb::{MaxMindDBError, Reader};
use maxminddb::geoip2::{City, Asn};

use std::net::IpAddr;
use std::str::FromStr;

use maxminddb;

lazy_static! {
    static ref CITY_READER: Reader<Vec<u8>> = Reader::open_readfile("geodata/mmdb/GeoLite2-City.mmdb").unwrap();
    static ref ASN_READER: Reader<Vec<u8>> = Reader::open_readfile("geodata/mmdb/GeoLite2-ASN.mmdb").unwrap();
}

pub fn city_lookup(ip: IpAddr) -> City {
    CITY_READER.lookup(ip).unwrap()
}

pub fn asn_lookup(ip: IpAddr) -> Asn {
    ASN_READER.lookup(ip).unwrap()
}

pub fn test_geo_lookup() {
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

}

pub fn test_lookups() {
    let ip: IpAddr = FromStr::from_str("1.1.1.1").unwrap();

    let city = city_lookup(ip);
    println!("city {:?}", city);

    let asn = asn_lookup(ip);
    println!("asn {:?}", asn);
}