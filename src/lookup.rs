use fastly::config_store::ConfigStore;
use fastly::error::anyhow;
use fastly::object_store::ObjectStore;
use fastly::Error;

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

struct ZoneStore {
    cs: ConfigStore,
    os: ObjectStore,
}

impl ZoneStore {
    fn open() -> Self {
        Self {
            // TODO handle errors
            cs: ConfigStore::open("cs_zones"),
            os: ObjectStore::open("os_zones").unwrap().unwrap(),
        }
    }

    #[instrument(skip(self))]
    fn get_rrmap_objectstore(&self, name: &str) -> Result<Option<String>, Error> {
        self.os.lookup_str(name).map_err(|err| anyhow!("{}", err))
    }

    #[instrument(skip(self))]
    fn get_rrmap_configstore(&self, name: &str) -> Result<Option<String>, Error> {
        self.cs.try_get(name).map_err(|err| anyhow!("{}", err))
    }

    // #[instrument(skip(self))]
    fn get_rrmap(&self, name: &str) -> Result<Option<JsonRRMap>, Error> {
        let rrmapstr = if name.ends_with(".os-example.com.") {
            self.get_rrmap_objectstore(name)
        } else {
            self.get_rrmap_configstore(name)
        };

        match rrmapstr {
            // found the json rrmap string - decode and return it
            Ok(Some(rrmapstr)) => match serde_json::from_str(&rrmapstr) {
                Ok(rrmap) => Ok(Some(rrmap)),
                Err(err) => {
                    error!("bad json in {}: {}", name, err);
                    Err(anyhow!("{}", err))
                }
            },

            // didn't find anything for this name
            Ok(None) => Ok(None),

            // something went wrong with the lookup
            Err(err) => {
                error!("lookup failed for {}: {}", name, err);
                Err(anyhow!("{}", err))
            }
        }
    }
}

#[instrument]
pub fn lookup(name: &Name, rr_type: RecordType) -> LookupResult {
    let mut result = LookupResult {
        rcode: ResponseCode::NoError,
        answers: Vec::new(),
        authority: Vec::new(),
        additionals: Vec::new(),
    };

    let store = ZoneStore::open();

    let mut lname = name.to_lowercase();
    lname.set_fqdn(true);

    // look for the name or the wildcard
    let mut rrmap = store.get_rrmap(&lname.to_string());
    match rrmap {
        Ok(None) => rrmap = store.get_rrmap(&lname.clone().into_wildcard().to_string()),
        _ => (),
    }

    match rrmap {
        Ok(Some(rrmap)) => {
            // name or wildcard exists; see if we
            // have answers for the requested rrtype
            debug!("{}: {:?}", lname, rrmap);
            result.answers = rrmap.get(name, rr_type);
            if result.answers.len() > 0 {
                return result;
            } else {
                // no answers; see if we can find the SOA
                result.authority = rrmap.get(name, RecordType::SOA);
                if result.authority.len() > 0 {
                    return result;
                }
            }
        }

        Ok(None) => {
            // name and wildcard don't exist
            result.rcode = ResponseCode::NXDomain;
        }

        _ => {
            // error during lookup or json decode
            result.rcode = ResponseCode::ServFail;
            return result;
        }
    }

    // If we got here we failed to find answers because the name
    // and wildcard don't exist or don't have records of rr_type.
    // Walk up the tree looking for the SOA at the top of the zone.
    // If we find it, add it to the authority section and return.
    // Otherwise return REFUSED because we don't serve this domain.

    lname = lname.base_name();
    while lname.num_labels() >= 2 {
        match store.get_rrmap(&lname.to_string()) {
            Ok(Some(rrmap)) => {
                debug!("{}: {:?}", lname, rrmap);
                result.authority = rrmap.get(name, RecordType::SOA);
                if result.authority.len() > 0 {
                    return result;
                }
                // name exists, but no SOA record
                lname = lname.base_name();
            }

            Ok(None) => {
                // name doesn't exist
                lname = lname.base_name();
            }

            _ => {
                // error during lookup or json decode
                result.rcode = ResponseCode::ServFail;
                return result;
            }
        }
    }

    result.rcode = ResponseCode::Refused;
    result
}
