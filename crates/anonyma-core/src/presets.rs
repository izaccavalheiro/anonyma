//! Compliance presets (`src/presets.ts`): the categories each regulation
//! covers and how they are anonymized.

use std::fmt;
use std::str::FromStr;

use crate::Category::{self, *};
use crate::{Error, StrategySpec};

/// A compliance preset of anonyma.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Preset {
    /// EU General Data Protection Regulation.
    Gdpr,
    /// Brazil's Lei Geral de Proteção de Dados.
    Lgpd,
    /// Canada's PIPEDA.
    Pipeda,
    /// US HIPAA Safe Harbor.
    Hipaa,
    /// California Consumer Privacy Act.
    Ccpa,
    /// PCI-DSS cardholder data.
    PciDss,
    /// Sarbanes-Oxley.
    Sox,
    /// FERPA education records.
    Ferpa,
}

impl Preset {
    /// Every preset.
    pub const ALL: &'static [Preset] = &[
        Preset::Gdpr,
        Preset::Lgpd,
        Preset::Pipeda,
        Preset::Hipaa,
        Preset::Ccpa,
        Preset::PciDss,
        Preset::Sox,
        Preset::Ferpa,
    ];

    /// The name of the preset (`pci-dss`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Preset::Gdpr => "gdpr",
            Preset::Lgpd => "lgpd",
            Preset::Pipeda => "pipeda",
            Preset::Hipaa => "hipaa",
            Preset::Ccpa => "ccpa",
            Preset::PciDss => "pci-dss",
            Preset::Sox => "sox",
            Preset::Ferpa => "ferpa",
        }
    }

    /// The categories the preset detects, in the reference's order.
    pub const fn categories(self) -> &'static [Category] {
        match self {
            Preset::Gdpr => &[
                Name,
                Email,
                Phone,
                Address,
                DateOfBirth,
                Ssn,
                NationalId,
                Passport,
                DriversLicense,
                Iban,
                BankAccount,
                CreditCard,
                Ipv4,
                Ipv6,
                Url,
                MedicalRecord,
                HealthInsurance,
                Prescription,
                SocialMedia,
                Cryptocurrency,
                TaxId,
            ],
            Preset::Hipaa => &[
                Name,
                Address,
                DateOfBirth,
                Phone,
                Email,
                Ssn,
                MedicalRecord,
                HealthInsurance,
                Prescription,
                BankAccount,
                CreditCard,
                Iban,
                DriversLicense,
                Passport,
                Vin,
                LicensePlate,
                Url,
                Ipv4,
                Ipv6,
                NationalId,
                TaxId,
                SocialMedia,
                CompanyRegistration,
            ],
            Preset::Ccpa => &[
                Name,
                Email,
                Phone,
                Address,
                Ssn,
                NationalId,
                Passport,
                DriversLicense,
                BankAccount,
                CreditCard,
                TaxId,
                Ipv4,
                Ipv6,
                Url,
                SocialMedia,
                DateOfBirth,
                MedicalRecord,
                HealthInsurance,
                ApiKey,
            ],
            Preset::Lgpd => &[
                Name,
                Email,
                Phone,
                Address,
                DateOfBirth,
                NationalId,
                TaxId,
                Passport,
                DriversLicense,
                BankAccount,
                Iban,
                CreditCard,
                Cryptocurrency,
                Ipv4,
                Ipv6,
                Url,
                SocialMedia,
                LicensePlate,
                MedicalRecord,
                HealthInsurance,
                Prescription,
            ],
            Preset::Pipeda => &[
                Name,
                Email,
                Phone,
                Address,
                DateOfBirth,
                NationalId,
                Ssn,
                Passport,
                DriversLicense,
                TaxId,
                BankAccount,
                Iban,
                CreditCard,
                Ipv4,
                Ipv6,
                SocialMedia,
                MedicalRecord,
                HealthInsurance,
                Prescription,
            ],
            Preset::PciDss => &[CreditCard, BankAccount, Name, Address, Email, Phone],
            Preset::Sox => &[
                Name,
                Email,
                TaxId,
                BankAccount,
                CompanyRegistration,
                Ssn,
                Address,
                Phone,
            ],
            Preset::Ferpa => &[Name, Email, Phone, Address, DateOfBirth, Ssn, NationalId],
        }
    }

    /// The strategy of the categories that have no rule of their own.
    pub fn default_strategy(self) -> StrategySpec {
        match self {
            Preset::Gdpr => StrategySpec::pseudonymize(),
            _ => StrategySpec::redact(),
        }
    }

    /// The categories with a strategy of their own.
    pub fn rules(self) -> Vec<(Category, StrategySpec)> {
        match self {
            Preset::PciDss => vec![
                (CreditCard, StrategySpec::mask_trailing(4)),
                (BankAccount, StrategySpec::mask_trailing(4)),
            ],
            _ => Vec::new(),
        }
    }
}

impl FromStr for Preset {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        Preset::ALL
            .iter()
            .copied()
            .find(|preset| preset.as_str() == name)
            .ok_or_else(|| Error::UnknownPreset(name.to_string()))
    }
}

impl fmt::Display for Preset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Presets combined, for data under several regulations at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedPreset {
    /// The presets, without duplicates, in the order given.
    pub names: Vec<Preset>,
    /// Every category of every preset, in first-seen order.
    pub categories: Vec<Category>,
    /// The most protective default strategy.
    pub default_strategy: StrategySpec,
    /// Categories whose most protective strategy differs from the default.
    pub rules: Vec<(Category, StrategySpec)>,
}

/// The first of the most protective strategies, as the reference ranks them.
fn strongest(strategies: impl IntoIterator<Item = StrategySpec>) -> Option<StrategySpec> {
    strategies.into_iter().reduce(|best, strategy| {
        if strategy.exposure() < best.exposure() {
            strategy
        } else {
            best
        }
    })
}

/// Combine presets as the reference's `combinePresets()`: every category of
/// every preset, each with the most protective strategy among the presets that
/// cover it.
pub fn combine(presets: &[Preset]) -> Result<CombinedPreset, Error> {
    let mut names: Vec<Preset> = Vec::new();
    for &preset in presets {
        if !names.contains(&preset) {
            names.push(preset);
        }
    }
    let Some(&first) = names.first() else {
        return Err(Error::validation("preset", "must name at least one preset"));
    };
    if names.len() == 1 {
        return Ok(CombinedPreset {
            names,
            categories: first.categories().to_vec(),
            default_strategy: first.default_strategy(),
            rules: first.rules(),
        });
    }

    let mut categories: Vec<Category> = Vec::new();
    for preset in &names {
        for &category in preset.categories() {
            if !categories.contains(&category) {
                categories.push(category);
            }
        }
    }
    let default_strategy =
        strongest(names.iter().map(|p| p.default_strategy())).expect("at least one preset");
    let mut rules = Vec::new();
    for &category in &categories {
        let strategy = strongest(
            names
                .iter()
                .filter(|preset| preset.categories().contains(&category))
                .map(|preset| {
                    preset
                        .rules()
                        .into_iter()
                        .find(|(c, _)| *c == category)
                        .map_or_else(|| preset.default_strategy(), |(_, s)| s)
                }),
        )
        .expect("a category comes from at least one preset");
        if strategy != default_strategy {
            rules.push((category, strategy));
        }
    }
    Ok(CombinedPreset {
        names,
        categories,
        default_strategy,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for preset in Preset::ALL {
            assert_eq!(preset.as_str().parse::<Preset>(), Ok(*preset));
        }
        assert!("hippa".parse::<Preset>().is_err());
    }

    #[test]
    fn redaction_beats_a_mask_that_keeps_digits() {
        let combined = combine(&[Preset::PciDss, Preset::Hipaa]).unwrap();
        assert_eq!(combined.default_strategy, StrategySpec::redact());
        assert!(combined.rules.is_empty());
    }

    #[test]
    fn a_category_only_the_second_covers_keeps_its_strategy() {
        let combined = combine(&[Preset::Gdpr, Preset::Lgpd]).unwrap();
        assert_eq!(combined.default_strategy, StrategySpec::pseudonymize());
        assert_eq!(combined.rules, vec![(LicensePlate, StrategySpec::redact())]);
    }

    #[test]
    fn a_single_preset_keeps_its_rules() {
        assert_eq!(combine(&[Preset::PciDss]).unwrap().rules.len(), 2);
        assert!(combine(&[]).is_err());
    }
}
