use subtle::ConstantTimeEq;

use crate::{
    CryptoError, Result,
    duress::{
        DuressError, DuressUnlock, KeyWrapStorage, PersistentDuressState, ProfileRuntime,
        recover_pending_duress,
    },
    key_wrap::PinKeyWrap,
};

const PROFILE_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileKind {
    Real,
    Decoy,
}

#[derive(Debug)]
pub enum UnlockError<E> {
    Crypto(CryptoError),
    Storage(E),
}

pub struct PinVault {
    real_wrapped_key: PinKeyWrap,
    decoy_wrapped_key: PinKeyWrap,
    real_key_erased: bool,
}

impl PinVault {
    pub fn create(
        primary_pin: &str,
        duress_pin: &str,
        real_data_key: &[u8; PROFILE_KEY_LEN],
        decoy_data_key: &[u8; PROFILE_KEY_LEN],
    ) -> Result<Self> {
        if primary_pin.is_empty()
            || duress_pin.is_empty()
            || primary_pin.len() < 8
            || duress_pin.len() < 8
            || primary_pin.as_bytes().ct_eq(duress_pin.as_bytes()).into()
            || real_data_key.ct_eq(decoy_data_key).into()
        {
            return Err(CryptoError::InvalidPin);
        }
        let real_wrapped_key = PinKeyWrap::create(primary_pin, real_data_key)?;
        let decoy_wrapped_key = PinKeyWrap::create(duress_pin, decoy_data_key)?;
        Ok(Self {
            real_wrapped_key,
            decoy_wrapped_key,
            real_key_erased: false,
        })
    }

    /// Checks persistent duress state before attempting the real PIN path.
    /// On duress the in-memory real wrapper and runtime keys are zeroized before
    /// the storage adapter is asked to durably delete the real-key wrapper.
    pub fn unlock_with_storage<S: KeyWrapStorage>(
        &mut self,
        pin: &str,
        runtime: &mut ProfileRuntime,
        storage: &mut S,
    ) -> std::result::Result<ProfileKind, UnlockError<S::Error>> {
        let persisted_state = storage.duress_state().map_err(UnlockError::Storage)?;
        if persisted_state != PersistentDuressState::Normal {
            recover_pending_duress(runtime, storage).map_err(map_duress_error)?;
            let decoy = self
                .decoy_wrapped_key
                .unwrap(pin)
                .map_err(UnlockError::Crypto)?;
            if let Some(data_key) = decoy {
                runtime
                    .activate_decoy_profile(data_key)
                    .map_err(UnlockError::Crypto)?;
                return Ok(ProfileKind::Decoy);
            }
            return Err(UnlockError::Crypto(CryptoError::InvalidPin));
        }

        if self.real_key_erased {
            let decoy = self
                .decoy_wrapped_key
                .unwrap(pin)
                .map_err(UnlockError::Crypto)?;
            if let Some(data_key) = decoy {
                return (DuressUnlock {
                    decoy_data_key: data_key,
                })
                .activate(runtime, storage)
                .map_err(map_duress_error);
            }
            return Err(UnlockError::Crypto(CryptoError::InvalidPin));
        }

        let real = self
            .real_wrapped_key
            .unwrap(pin)
            .map_err(UnlockError::Crypto)?;
        let decoy = self
            .decoy_wrapped_key
            .unwrap(pin)
            .map_err(UnlockError::Crypto)?;
        if let Some(data_key) = real {
            runtime
                .activate_real_profile(data_key)
                .map_err(UnlockError::Crypto)?;
            return Ok(ProfileKind::Real);
        }
        if let Some(data_key) = decoy {
            self.real_wrapped_key.erase();
            self.real_key_erased = true;
            return (DuressUnlock {
                decoy_data_key: data_key,
            })
            .activate(runtime, storage)
            .map_err(map_duress_error);
        }
        Err(UnlockError::Crypto(CryptoError::InvalidPin))
    }

    pub fn real_key_erased(&self) -> bool {
        self.real_key_erased
    }
}

fn map_duress_error<E>(error: DuressError<E>) -> UnlockError<E> {
    match error {
        DuressError::Storage(error) => UnlockError::Storage(error),
        DuressError::Runtime(error) => UnlockError::Crypto(error),
    }
}

impl Drop for PinVault {
    fn drop(&mut self) {
        self.real_wrapped_key.erase();
        self.decoy_wrapped_key.erase();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duress::{DeletionReceipt, RuntimeProfileState};

    #[derive(Default)]
    struct MockKeyWrapStorage {
        state: PersistentDuressState,
        real_wrap_present: bool,
        fail_delete: bool,
        delete_calls: usize,
    }

    impl KeyWrapStorage for MockKeyWrapStorage {
        type Error = &'static str;

        fn duress_state(&mut self) -> std::result::Result<PersistentDuressState, Self::Error> {
            Ok(self.state)
        }

        fn mark_duress_pending_cleanup(&mut self) -> std::result::Result<(), Self::Error> {
            self.state = PersistentDuressState::PendingCleanup;
            Ok(())
        }

        fn delete_real_key_wrap(&mut self) -> std::result::Result<DeletionReceipt, Self::Error> {
            self.delete_calls += 1;
            if self.fail_delete {
                return Err("delete failed");
            }
            self.real_wrap_present = false;
            Ok(DeletionReceipt::confirmed())
        }

        fn mark_duress_active(&mut self) -> std::result::Result<(), Self::Error> {
            self.state = PersistentDuressState::Active;
            Ok(())
        }
    }

    #[test]
    fn primary_pin_unlocks_real_profile() {
        let real = [0x11; 32];
        let decoy = [0x22; 32];
        let mut vault = PinVault::create("primary-1842", "duress-7319", &real, &decoy).unwrap();
        let mut runtime = ProfileRuntime::locked();
        let mut storage = MockKeyWrapStorage::default();
        let opened = vault
            .unlock_with_storage("primary-1842", &mut runtime, &mut storage)
            .unwrap();
        assert_eq!(opened, ProfileKind::Real);
        assert_eq!(runtime.with_data_key(|key| *key).unwrap(), real);
        assert!(!vault.real_key_erased());
    }

    #[test]
    fn duress_pin_deletes_persistent_wrap_before_opening_decoy() {
        let real = [0x11; 32];
        let decoy = [0x22; 32];
        let mut vault = PinVault::create("primary-1842", "duress-7319", &real, &decoy).unwrap();
        let mut runtime = ProfileRuntime::with_real_profile(real);
        let mut storage = MockKeyWrapStorage {
            real_wrap_present: true,
            ..MockKeyWrapStorage::default()
        };
        let opened = vault
            .unlock_with_storage("duress-7319", &mut runtime, &mut storage)
            .unwrap();
        assert_eq!(opened, ProfileKind::Decoy);
        assert_eq!(runtime.with_data_key(|key| *key).unwrap(), decoy);
        assert_eq!(runtime.state(), RuntimeProfileState::Decoy);
        assert!(!runtime.has_real_material());
        assert_eq!(storage.state, PersistentDuressState::Active);
        assert!(!storage.real_wrap_present);
        assert_eq!(storage.delete_calls, 1);
        assert!(vault.real_key_erased());
        assert!(matches!(
            vault.unlock_with_storage("primary-1842", &mut runtime, &mut storage),
            Err(UnlockError::Crypto(CryptoError::InvalidPin))
        ));
    }

    #[test]
    fn wrong_and_duplicate_pins_are_rejected() {
        let key = [0x33; 32];
        let mut vault = PinVault::create("primary-1842", "duress-7319", &key, &[0x44; 32]).unwrap();
        let mut runtime = ProfileRuntime::locked();
        let mut storage = MockKeyWrapStorage::default();
        assert!(matches!(
            vault.unlock_with_storage("wrong", &mut runtime, &mut storage),
            Err(UnlockError::Crypto(CryptoError::InvalidPin))
        ));
        assert!(matches!(
            PinVault::create("same-pin-123", "same-pin-123", &key, &[0x44; 32]),
            Err(CryptoError::InvalidPin)
        ));
        assert!(matches!(
            PinVault::create("short", "duress-7319", &key, &[0x44; 32]),
            Err(CryptoError::InvalidPin)
        ));
        assert!(matches!(
            PinVault::create("primary-1842", "duress-7319", &key, &key),
            Err(CryptoError::InvalidPin)
        ));
    }

    #[test]
    fn deletion_failure_stays_pending_and_retries_before_decoy_unlock() {
        let real = [0x11; 32];
        let decoy = [0x22; 32];
        let mut vault = PinVault::create("primary-1842", "duress-7319", &real, &decoy).unwrap();
        let mut runtime = ProfileRuntime::with_real_profile(real);
        let mut storage = MockKeyWrapStorage {
            real_wrap_present: true,
            fail_delete: true,
            ..MockKeyWrapStorage::default()
        };
        assert!(matches!(
            vault.unlock_with_storage("duress-7319", &mut runtime, &mut storage),
            Err(UnlockError::Storage("delete failed"))
        ));
        assert!(vault.real_key_erased());
        assert_eq!(runtime.state(), RuntimeProfileState::DuressPendingCleanup);
        assert!(!runtime.has_real_material());
        assert_eq!(storage.state, PersistentDuressState::PendingCleanup);

        let mut restarted_runtime = ProfileRuntime::locked();
        storage.fail_delete = false;
        assert!(recover_pending_duress(&mut restarted_runtime, &mut storage).unwrap());
        assert_eq!(restarted_runtime.state(), RuntimeProfileState::Decoy);
        assert_eq!(storage.state, PersistentDuressState::Active);
        assert!(!storage.real_wrap_present);

        let opened = vault
            .unlock_with_storage("duress-7319", &mut restarted_runtime, &mut storage)
            .unwrap();
        assert_eq!(opened, ProfileKind::Decoy);
        assert_eq!(restarted_runtime.with_data_key(|key| *key).unwrap(), decoy);
        assert!(matches!(
            vault.unlock_with_storage("primary-1842", &mut restarted_runtime, &mut storage),
            Err(UnlockError::Crypto(CryptoError::InvalidPin))
        ));
    }
}
