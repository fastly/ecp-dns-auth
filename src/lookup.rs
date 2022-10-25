use std::net::{Ipv4Addr, Ipv6Addr};

use fastly::config_store::ConfigStore;
use serde::Deserialize;
use tracing::{debug, error, instrument};

use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::rdata;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

pub struct LookupResult {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additionals: Vec<Record>,
}

#[instrument]
pub fn lookup(name: &Name, rr_type: RecordType) -> LookupResult {
    let mut result = LookupResult {
        rcode: ResponseCode::NoError,
        answers: Vec::new(),
        authority: Vec::new(),
        additionals: Vec::new(),
    };

    // let store = ConfigStore::open("zones"); // edge dictionary
    let store = ConfigStore::open("cs_zones");

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
                    error!("bad json data in {} or wildcard: {}", name, err);
                    result.rcode = ResponseCode::ServFail;
                    return result;
                }
            };
            debug!("{}: {:?}", lname, rrmap);
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
    // Check the current rrs and then walk up the tree looking for
    // the SOA record at the top of the zone.
    // If we find it, add it to the authority section and return.
    // Otherwise return REFUSED because we don't serve this domain.

    // TODO we already have the rrmap for the current name above;
    // check it before walking up the tree and start with:
    // lname = lname.base_name();

    while lname.num_labels() >= 2 {
        match store.get(&lname.to_string()) {
            Some(rrmapstr) => {
                // found a name; decode the rr map
                let rrmap: JsonRRMap = match serde_json::from_str(&rrmapstr) {
                    Ok(rrmap) => rrmap,
                    Err(err) => {
                        error!("bad json data in {}: {}", name, err);
                        result.rcode = ResponseCode::ServFail;
                        return result;
                    }
                };
                debug!("{}: {:?}", lname, rrmap);
                match rrmap.SOA {
                    Some(soa) => {
                        result.authority = soa.to_rrs(&lname);
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
    AAAA: Option<JsonAAAA>,
    MX: Option<JsonMX>,
    NS: Option<JsonNS>,
    SOA: Option<JsonSOA>,
}

#[derive(Deserialize, Debug)]
struct JsonA {
    ttl: u32,
    values: Vec<Ipv4Addr>,
}

impl JsonA {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| Record::from_rdata(name.clone(), self.ttl, RData::A(*v)))
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonAAAA {
    ttl: u32,
    values: Vec<Ipv6Addr>,
}

impl JsonAAAA {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| Record::from_rdata(name.clone(), self.ttl, RData::AAAA(*v)))
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonMXValue {
    exchange: Name,
    preference: u16,
}

#[derive(Deserialize, Debug)]
struct JsonMX {
    ttl: u32,
    values: Vec<JsonMXValue>,
}

impl JsonMX {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| {
                Record::from_rdata(
                    name.clone(),
                    self.ttl,
                    RData::MX(rdata::MX::new(v.preference, v.exchange.clone())),
                )
            })
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonNS {
    ttl: u32,
    values: Vec<Name>,
}

impl JsonNS {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        self.values
            .iter()
            .map(|v| Record::from_rdata(name.clone(), self.ttl, RData::NS(v.clone())))
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct JsonSOAValue {
    mname: Name,
    rname: Name,
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

impl JsonSOA {
    fn to_rrs(&self, name: &Name) -> Vec<Record> {
        vec![Record::from_rdata(
            name.clone(),
            self.ttl,
            RData::SOA(rdata::SOA::new(
                self.value.mname.clone(),
                self.value.rname.clone(),
                self.value.serial,
                self.value.refresh,
                self.value.retry,
                self.value.expire,
                self.value.minimum,
            )),
        )]
    }
}

fn decode_json_rrs(name: &Name, rr_type: RecordType, rrmap: &JsonRRMap) -> Vec<Record> {
    match (rr_type, rrmap) {
        (RecordType::A, JsonRRMap { A: Some(a), .. }) => a.to_rrs(name),
        (
            RecordType::AAAA,
            JsonRRMap {
                AAAA: Some(aaaa), ..
            },
        ) => aaaa.to_rrs(name),
        (RecordType::MX, JsonRRMap { MX: Some(mx), .. }) => mx.to_rrs(name),
        (RecordType::NS, JsonRRMap { NS: Some(ns), .. }) => ns.to_rrs(name),
        (RecordType::SOA, JsonRRMap { SOA: Some(soa), .. }) => soa.to_rrs(name),
        _ => Vec::new(), // couldn't find rrs of the requested type
    }
}
