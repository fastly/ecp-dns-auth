use std::str::FromStr;

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

// TODO there has to be a simpler way to
// wrap either Config or Object store.
enum DataStore {
    ConfigStore(ConfigStore),
    ObjectStore(ObjectStore),
}

struct ZoneStore {
    ds: DataStore,
}

impl ZoneStore {
    // TODO handle errors
    #[instrument(skip_all)]
    fn open(name: &Name) -> Self {
        // For testing we store os-example.com in the Object store
        // and everything else in the Config store.
        // TODO decide on one and use it alone.
        if Name::from_str("os-example.com.").unwrap().zone_of(name) {
            debug!("using ObjectStore for: {}", name);
            let os = ObjectStore::open("os_zones").unwrap().unwrap();
            Self {
                ds: DataStore::ObjectStore(os),
            }
        } else {
            debug!("using ConfigStore for: {}", name);
            let cs = ConfigStore::open("cs_zones");
            Self {
                ds: DataStore::ConfigStore(cs),
            }
        }
    }

    #[instrument(skip(self))]
    fn get_rrmapstr(&self, name: &str) -> Result<Option<String>, Error> {
        let rrmapstr = match &self.ds {
            DataStore::ObjectStore(os) => os.lookup_str(name).map_err(|err| anyhow!("{}", err)),
            DataStore::ConfigStore(cs) => cs.try_get(name).map_err(|err| anyhow!("{}", err)),
        };
        debug!("{}: {:?}", name, rrmapstr);
        rrmapstr
    }

    #[instrument(skip_all)]
    fn decode_rrmap(&self, rrmapstr: &str) -> Result<JsonRRMap, serde_json::Error> {
        serde_json::from_str(rrmapstr)
    }

    fn get_rrmap(&self, name: &str) -> Result<Option<JsonRRMap>, Error> {
        match self.get_rrmapstr(name) {
            // found the json rrmap string - decode and return it
            Ok(Some(rrmapstr)) => match self.decode_rrmap(&rrmapstr) {
                Ok(rrmap) => Ok(Some(rrmap)),
                Err(err) => {
                    error!("bad json in {}: {}", name, err);
                    Err(anyhow!("{}", err))
                }
            },

            // didn't find anything for this name
            Ok(None) => {
                debug!("name: {} not found", name);
                Ok(None)
            }

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

    // not hosting any TLDs for now
    if name.num_labels() < 2 {
        result.rcode = ResponseCode::Refused;
        return result;
    }

    let mut lname = name.to_lowercase();
    lname.set_fqdn(true);

    let store = ZoneStore::open(&lname);

    // look for the name or the wildcard
    let mut rrmap = store.get_rrmap(&lname.to_string());
    match rrmap {
        Ok(None) if lname.num_labels() > 2 => {
            rrmap = store.get_rrmap(&lname.clone().into_wildcard().to_string())
        }
        _ => (),
    }

    match rrmap {
        Ok(Some(rrmap)) => {
            // name or wildcard exists; see if we
            // have answers for the requested rrtype
            debug!("{}: {:?}", lname, rrmap);
            result.answers = rrmap.get_rrs(name, rr_type);
            if result.answers.len() > 0 {
                return result;
            } else {
                // no answers; see if we can find the SOA
                result.authority = rrmap.get_rrs(name, RecordType::SOA);
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
                result.authority = rrmap.get_rrs(name, RecordType::SOA);
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
