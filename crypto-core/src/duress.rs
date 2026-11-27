use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, Result, session::SessionState, vault::ProfileKind};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PersistentDuressState {
    #[default]
    Normal,
    PendingCleanup,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeProfileState {
    Locked,
    Real,
    DuressPendingCleanup,
    Decoy,
}

/// A storage adapter must only issue this receipt after the key-wrap deletion
/// is durably committed. This does not imply physical erasure of SSD sectors,
/// filesystem journals, swap, or operating-system backups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionReceipt(());

impl DeletionReceipt {
    pub fn confirmed() -> Self {
        Self(())
    }
}

pub trait KeyWrapStorage {
    type Error;

    fn duress_state(&mut self) -> std::result::Result<PersistentDuressState, Self::Error>;

    /// Durably records DURESS_PENDING_CLEANUP before deletion is attempted.
    fn mark_duress_pending_cleanup(&mut self) -> std::result::Result<(), Self::Error>;

    /// Must be idempotent and only return a receipt after durable deletion.
    fn delete_real_key_wrap(&mut self) -> std::result::Result<DeletionReceipt, Self::Error>;

    fn mark_duress_active(&mut self) -> std::result::Result<(), Self::Error>;
}

pub struct ProfileRuntime {
    state: RuntimeProfileState,
    profile_data_key: Option<Zeroizing<[u8; 32]>>,
    sessions: Vec<SessionState>,
}

impl ProfileRuntime {
    pub fn locked() -> Self {
        Self {
            state: RuntimeProfileState::Locked,
            profile_data_key: None,
            sessions: Vec::new(),
        }
    }

    pub fn with_real_profile(data_key: [u8; 32]) -> Self {
        Self {
            state: RuntimeProfileState::Real,
            profile_data_key: Some(Zeroizing::new(data_key)),
            sessions: Vec::new(),
        }
    }

    pub fn with_data_key<T>(&self, action: impl FnOnce(&[u8; 32]) -> T) -> Result<T> {
        self.profile_data_key
            .as_deref()
            .map(action)
            .ok_or(CryptoError::InvalidProfileState)
    }

    pub fn add_session(&mut self, session: SessionState) -> Result<()> {
        if !matches!(
            self.state,
            RuntimeProfileState::Real | RuntimeProfileState::Decoy
        ) || self.profile_data_key.is_none()
        {
            return Err(CryptoError::InvalidProfileState);
        }
        self.sessions.push(session);
        Ok(())
    }

    pub fn state(&self) -> RuntimeProfileState {
        self.state
    }

    pub fn has_real_material(&self) -> bool {
        self.state == RuntimeProfileState::Real
            && (self.profile_data_key.is_some() || !self.sessions.is_empty())
    }

    fn erase_real_material(&mut self) {
        if let Some(mut key) = self.profile_data_key.take() {
            key.zeroize();
        }
        self.sessions.clear();
        self.state = RuntimeProfileState::DuressPendingCleanup;
    }

    pub(crate) fn activate_real_profile(&mut self, data_key: Zeroizing<[u8; 32]>) -> Result<()> {
        if self.state != RuntimeProfileState::Locked {
            return Err(CryptoError::InvalidProfileState);
        }
        self.profile_data_key = Some(data_key);
        self.state = RuntimeProfileState::Real;
        Ok(())
    }

    pub(crate) fn activate_decoy_profile(&mut self, data_key: Zeroizing<[u8; 32]>) -> Result<()> {
        if !matches!(
            self.state,
            RuntimeProfileState::DuressPendingCleanup | RuntimeProfileState::Decoy
        ) {
            return Err(CryptoError::InvalidProfileState);
        }
        self.profile_data_key = Some(data_key);
        self.state = RuntimeProfileState::Decoy;
        Ok(())
    }
}

#[derive(Debug)]
pub enum DuressError<E> {
    Storage(E),
    Runtime(CryptoError),
}

pub(crate) struct DuressUnlock {
    pub(crate) decoy_data_key: Zeroizing<[u8; 32]>,
}

impl DuressUnlock {
    pub(crate) fn activate<S: KeyWrapStorage>(
        self,
        runtime: &mut ProfileRuntime,
        storage: &mut S,
    ) -> std::result::Result<ProfileKind, DuressError<S::Error>> {
        runtime.erase_real_material();
        storage
            .mark_duress_pending_cleanup()
            .map_err(DuressError::Storage)?;
        delete_real_key_wrap(storage)?;
        storage.mark_duress_active().map_err(DuressError::Storage)?;

        runtime
            .activate_decoy_profile(self.decoy_data_key)
            .map_err(DuressError::Runtime)?;
        Ok(ProfileKind::Decoy)
    }
}

/// Must be called before unlocking any profile at startup. Pending cleanup is
/// retried idempotently; the real profile remains unavailable until a durable
/// deletion receipt is returned.
pub fn recover_pending_duress<S: KeyWrapStorage>(
    runtime: &mut ProfileRuntime,
    storage: &mut S,
) -> std::result::Result<bool, DuressError<S::Error>> {
    let persisted_state = storage.duress_state().map_err(DuressError::Storage)?;
    if persisted_state == PersistentDuressState::Normal {
        return Ok(false);
    }

    runtime.erase_real_material();
    delete_real_key_wrap(storage)?;
    storage.mark_duress_active().map_err(DuressError::Storage)?;
    runtime.state = RuntimeProfileState::Decoy;
    Ok(true)
}

fn delete_real_key_wrap<S: KeyWrapStorage>(
    storage: &mut S,
) -> std::result::Result<DeletionReceipt, DuressError<S::Error>> {
    storage.delete_real_key_wrap().map_err(DuressError::Storage)
}
