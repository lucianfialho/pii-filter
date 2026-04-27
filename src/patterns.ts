export const PII_PATTERNS: Array<{ type: string; regex: RegExp }> = [
  { type: "PRIVATE_EMAIL", regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g },
  { type: "PRIVATE_PHONE", regex: /(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\s?)?\d{4}[-\s]?\d{4}\b/g },
  { type: "PRIVATE_PHONE", regex: /\+?1?\s?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g },
  { type: "ACCOUNT_NUMBER", regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g }, // CPF
  { type: "ACCOUNT_NUMBER", regex: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g }, // CNPJ
  { type: "ACCOUNT_NUMBER", regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g }, // credit card
  { type: "SECRET", regex: /\b(?:sk|pk|api[_-]?key|token|secret|password|passwd|pwd)[_\-\s]*[:=]\s*['"]?[\w\-./+]{8,}['"]?/gi },
  { type: "PRIVATE_URL", regex: /https?:\/\/[^\s"']+(?:token|key|secret|password|auth)[^\s"']*/gi },
];

export const PII_FIELD_NAMES = new Set([
  "email", "e_mail", "user_email", "customer_email",
  "phone", "phone_number", "mobile", "telefone", "celular",
  "cpf", "cnpj", "ssn", "tax_id",
  "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
  "credit_card", "card_number", "cvv",
  "name", "full_name", "first_name", "last_name", "nome",
  "address", "street", "endereco", "zip", "cep",
  "birth_date", "birthdate", "data_nascimento", "dob",
]);
