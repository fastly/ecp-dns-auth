use fastly::config_store::ConfigStore;
use tracing::{debug, error, instrument};

use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::{Name, Record, RecordType};

use crate::dns::JsonRRMap;

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
            result.answers = rrmap.get(name, rr_type);
        }
        _ => {
            // name and wildcard don't exist
            result.rcode = ResponseCode::NXDomain;
        }
    }

    if result.answers.len() > 0 {
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
                result.authority = rrmap.get(&lname, RecordType::SOA);
                if result.authority.len() > 0 {
                    return result;
                } else {
                    // name exists, but no soa record
                    lname = lname.base_name();
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
