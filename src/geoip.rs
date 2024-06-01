use lazy_static::lazy_static;
use maxminddb::geoip2::{Asn, City};
use maxminddb::{MaxMindDBError, Reader};

use std::net::IpAddr;
use std::str::FromStr;

use maxminddb;

lazy_static! {
    static ref CITY_READER: Reader<Vec<u8>> =
        Reader::open_readfile("geodata/mmdb/GeoLite2-City.mmdb").unwrap();
    static ref ASN_READER: Reader<Vec<u8>> =
        Reader::open_readfile("geodata/mmdb/GeoLite2-ASN.mmdb").unwrap();
}

// TODO filter internal network ip address and do not panic here!
pub fn city_lookup(ip: IpAddr) -> Result<City<'static>, MaxMindDBError> {
    CITY_READER.lookup(ip)
}

pub fn asn_lookup(ip: IpAddr) -> Result<Asn<'static>, MaxMindDBError> {
    ASN_READER.lookup(ip)
}

pub fn test_geo_lookup() {
    let filename = "geodata/mmdb/GeoLite2-City.mmdb";
    let reader = Reader::open_readfile(filename).unwrap();

    let ip: IpAddr = FromStr::from_str("1.1.1.1").unwrap();
    // 89.160.20.112
    let city: City = reader.lookup(ip).unwrap();

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
