//! PII categories, their token prefixes and how far this crate detects them.

use std::fmt;
use std::str::FromStr;

use crate::Error;

macro_rules! categories {
    ($( $variant:ident => $name:literal, $prefix:literal, $support:ident; )*) => {
        /// A category of personal data: the 27 categories of anonyma.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Category {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )*
        }

        impl Category {
            /// Every category, in the order of anonyma's `ALL_CATEGORIES`.
            pub const ALL: &'static [Category] = &[$(Category::$variant),*];

            /// The name of the category, as anonyma spells it (`credit-card`).
            pub const fn as_str(self) -> &'static str {
                match self { $(Category::$variant => $name),* }
            }

            /// The prefix of its tokens (`CREDIT_CARD` in `{{CREDIT_CARD_1}}`).
            pub const fn token_prefix(self) -> &'static str {
                match self { $(Category::$variant => $prefix),* }
            }

            /// How far this crate detects the category.
            pub const fn support(self) -> Support {
                match self { $(Category::$variant => Support::$support),* }
            }
        }

        impl FromStr for Category {
            type Err = Error;

            fn from_str(name: &str) -> Result<Self, Error> {
                match name {
                    $($name => Ok(Category::$variant),)*
                    _ => Err(Error::UnknownCategory(name.to_string())),
                }
            }
        }
    };
}

categories! {
    Email => "email", "EMAIL", Full;
    Phone => "phone", "PHONE", Full;
    Ssn => "ssn", "SSN", Full;
    CreditCard => "credit-card", "CREDIT_CARD", Full;
    Ipv4 => "ipv4", "IPV4", Full;
    Ipv6 => "ipv6", "IPV6", Full;
    Url => "url", "URL", Full;
    Iban => "iban", "IBAN", Full;
    DateOfBirth => "date-of-birth", "DATE", Full;
    Name => "name", "PERSON", Full;
    Address => "address", "ADDRESS", Full;
    Passport => "passport", "PASSPORT", Full;
    DriversLicense => "drivers-license", "DRIVERS_LICENSE", Full;
    NationalId => "national-id", "NATIONAL_ID", Full;
    BankAccount => "bank-account", "BANK_ACCOUNT", Full;
    Cryptocurrency => "cryptocurrency", "CRYPTO", Full;
    TaxId => "tax-id", "TAX_ID", Full;
    MedicalRecord => "medical-record", "MEDICAL_RECORD", Full;
    HealthInsurance => "health-insurance", "HEALTH_INSURANCE", Full;
    Prescription => "prescription", "PRESCRIPTION", Full;
    ApiKey => "api-key", "API_KEY", Full;
    SocialMedia => "social-media", "SOCIAL_MEDIA", Full;
    Vin => "vin", "VIN", Full;
    LicensePlate => "license-plate", "LICENSE_PLATE", Full;
    TrackingNumber => "tracking-number", "TRACKING_NUMBER", Full;
    CaseNumber => "case-number", "CASE_NUMBER", Full;
    CompanyRegistration => "company-registration", "COMPANY_REG", Full;
}

/// How far `anonyma-core` detects a category, compared with the TypeScript
/// reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Every pattern of the reference detector, conformance-tested.
    Full,
    /// Some entries of a composite detector, conformance-tested on inputs
    /// that only those entries match. No category is partial at present.
    Partial,
    /// Not ported yet. Every category is ported at present.
    None,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        assert_eq!(Category::ALL.len(), 27);
        for category in Category::ALL {
            assert_eq!(category.as_str().parse::<Category>(), Ok(*category));
        }
        assert!("nope".parse::<Category>().is_err());
    }

    #[test]
    fn prefixes_match_the_reference() {
        assert_eq!(Category::Name.token_prefix(), "PERSON");
        assert_eq!(Category::DateOfBirth.token_prefix(), "DATE");
        assert_eq!(Category::CompanyRegistration.token_prefix(), "COMPANY_REG");
    }
}
