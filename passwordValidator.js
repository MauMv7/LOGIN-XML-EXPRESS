const hasValidLength = (password) => password.length >= 8;
const hasUpperCase = (password) => /[A-Z]/.test(password);
const hasLowerCase = (password) => /[a-z]/.test(password);
const hasSpecialChar = (password) => /[.\-_!$@?%#&]/.test(password);
const hasNoSequences = (password) => {
    const sequences = ['123', '234', '345', '456', '567', '678', '789', '012', '000', '111', '222', '333', '444', '555', '666', '777', '888', '999',
        'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
        'ABC', 'BCD', 'CDE', 'DEF', 'EFG', 'FGH', 'GHI', 'HIJ', 'IJK', 'JKL', 'KLM', 'LMN', 'MNO', 'NOP', 'OPQ', 'PQR', 'QRS', 'RST', 'STU', 'TUV', 'UVW', 'VWX', 'WXY', 'XYZ'];
    return !sequences.some(seq => password.includes(seq));
}

const validatePassword = (password) => {
    if (!hasValidLength(password)) {
        return 'La contraseña debe tener al menos 8 caracteres.';
    }
    if (!hasUpperCase(password)) {
        return 'La contraseña debe tener al menos una letra mayúscula.';
    }
    if (!hasLowerCase(password)) {
        return 'La contraseña debe tener al menos una letra minúscula.';
    }
    if (!hasSpecialChar(password)) {
        return 'La contraseña debe tener al menos un carácter especial de los válidos: ._-!$@?%#&';
    }
    if (!hasNoSequences(password)) {
        return 'La contraseña no debe contener secuencias o series: ABC, xyz, 123, 987, 000, etc.';
    }
    return null;
}

module.exports = validatePassword;
