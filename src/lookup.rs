use std::net::Ipv4Addr;
use std::str::FromStr;

use fastly::config_store::ConfigStore;
use serde::Deserialize;

use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::rdata;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

pub struct LookupResult {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additionals: Vec<Record>,
}

pub fn lookup(name: &Name, rr_type: RecordType) -> LookupResult {
    println!("lookup {}:{}", name, rr_type);

    let mut result = LookupResult {
        rcode: ResponseCode::NoError,
        answers: Vec::new(),
        authority: Vec::new(),
        additionals: Vec::new(),
    };

    let store = ConfigStore::open("zones");

    // look for the name or the wildcard
    let mut lname = name.to_lowercase();
    lname.set_fqdn(true);
    match store
        .get(&lname.to_string())
        .or_else(|| store.get(&lname.clone().into_wildcard().to_string()))
    {
        Some(rrmapstr) => {
            // found something; decode the rr map
            let rrmap: JsonRRMap = match serde_json::from_str(&rrmapstr) {
                Ok(rrmap) => rrmap,
                Err(err) => {
                    println!("ERROR: bad json data in {} or wildcard: {}", name, err);
                    result.rcode = ResponseCode::ServFail;
                    return result;
                }
            };
            println!("{}: {:?}", lname, rrmap);
            result.answers = decode_json_rrs(name, rr_type, &rrmap);
        }
        _ => {
            // name and wildcard don't exist
            result.rcode = ResponseCode::NXDomain;
        }
    }

    if result.answers.len() >= 1 {
        return result;
    }

    // If we got here we failed to find answers because the name
    // and wildcard don't exist or don't have records of rr_type.
    // Walk up the tree looking for the SOA record at the top of the zone.
    // If we find it, add it to the authority section and return.
    // Otherwise return REFUSED because we don't serve this domain.
    lname = lname.base_name();
    while lname.num_labels() >= 2 {
        println!("lookup {}:SOA", lname);
        match store.get(&lname.to_string()) {
            Some(rrmapstr) => {
                // found a name; decode the rr map
                let rrmap: JsonRRMap = match serde_json::from_str(&rrmapstr) {
                    Ok(rrmap) => rrmap,
                    Err(err) => {
                        println!("ERROR: bad json data in {}: {}", name, err);
                        result.rcode = ResponseCode::ServFail;
                        return result;
                    }
                };
                println!("{}: {:?}", lname, rrmap);
                match rrmap.SOA {
                    Some(rrs) => {
                        result.authority = json_soa(name, &rrs);
                        return result;
                    }
                    _ => {
                        // name exists, but no SOA record
                        lname = lname.base_name();
                    }
                }
            }
            _ => {
                // name doesn't exist
                lname = lname.base_name();
            }
        }
    }

    result.rcode = ResponseCode::Refused;
    result
}

#[derive(Deserialize, Debug)]
struct JsonRRMap {
    A: Option<JsonA>,
    SOA: Option<JsonSOA>,
}

#[derive(Deserialize, Debug)]
struct JsonA {
    ttl: u32,
    values: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct JsonSOAValue {
    mname: String,
    rname: String,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

#[derive(Deserialize, Debug)]
struct JsonSOA {
    ttl: u32,
    value: JsonSOAValue,
}

fn decode_json_rrs(name: &Name, rr_type: RecordType, rrmap: &JsonRRMap) -> Vec<Record> {
    match (rr_type, rrmap) {
        (RecordType::A, JsonRRMap { A: Some(A), .. }) => json_a(name, A),
        _ => Vec::new(), // couldn't find rrs of the requested type
    }
}

fn json_soa(name: &Name, rrs: &JsonSOA) -> Vec<Record> {
    vec![Record::from_rdata(
        name.clone(),
        rrs.ttl,
        RData::SOA(rdata::SOA::new(
            // TODO handle errors here
            Name::from_str(&rrs.value.mname).unwrap(),
            Name::from_str(&rrs.value.rname).unwrap(),
            rrs.value.serial,
            rrs.value.refresh,
            rrs.value.retry,
            rrs.value.expire,
            rrs.value.minimum,
        )),
    )]
}

fn json_a(name: &Name, rrs: &JsonA) -> Vec<Record> {
    rrs.values
        .iter()
        .map(|v| {
            Record::from_rdata(
                name.clone(),
                rrs.ttl,
                // TODO handle errors here
                RData::A(Ipv4Addr::from_str(v).unwrap()),
            )
        })
        .collect()
}
