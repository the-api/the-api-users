export const USER_HIDDEN_FIELDS = [
  'password',
  'salt',
  'refresh',
  'timeRefreshExpired',
  'registerCode',
  'registerCodeAttempts',
  'timeRegisterCodeExpired',
  'recoverCode',
  'recoverCodeAttempts',
  'timeRecoverCodeExpired',
  'phoneCode',
  'phoneCodeAttempts',
  'timePhoneCodeExpired',
  'phoneChangeCode',
  'phoneChangeCodeAttempts',
  'timePhoneChangeCodeExpired',
  'phoneToChange',
  'emailChangeCode',
  'emailChangeCodeAttempts',
  'timeEmailChangeCodeExpired',
  'emailToChange',
  'oauthProviders',
  'email',
  'phone',
  'bannedCode',
  'bannedReason',
  'bannedAt',
  'bannedUntil',
];

export const USER_VISIBLE_FOR = {
  'users.viewEmail': ['email', 'isEmailVerified'],
  'users.viewPhone': ['phone', 'isPhoneVerified'],
  'users.viewRole': ['role'],
  'users.viewLocale': ['locale', 'timezone'],
  'users.viewStatus': ['isBanned', 'isDeleted', 'isEmailInvalid', 'isPhoneInvalid'],
  'users.viewBanDetails': ['bannedCode', 'bannedReason', 'bannedAt', 'bannedUntil'],
  'users.viewMeta': ['timeCreated', 'timeUpdated', 'timeDeleted'],
};

export const USER_OWNER_PERMISSIONS = [
  'users.viewEmail',
  'users.viewPhone',
  'users.viewRole',
  'users.viewLocale',
  'users.viewBanDetails',
  'users.viewMeta',
];

export const USER_EDITABLE_FOR = {
  'users.editProfile': ['fullName', 'locale', 'timezone'],
  'users.editEmail': ['email'],
  'users.editPhone': ['phone'],
  'users.editRole': ['role'],
  'users.editStatus': [
    'isBanned',
    'bannedCode',
    'bannedReason',
    'bannedAt',
    'bannedUntil',
    'isDeleted',
    'isEmailInvalid',
    'isPhoneInvalid',
  ],
  'users.editVerification': ['isEmailVerified', 'isPhoneVerified'],
};

export const USER_SELF_EDITABLE_FIELDS = ['fullName', 'locale', 'timezone'];
