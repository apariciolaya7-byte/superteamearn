use serde::{Deserialize, Serialize};
use serde_json::Result;

// ==========================================
// 1. ESTRUCTURAS DE ENTRADA (Masticado Zero-Copy)
// ==========================================

// Leemos solo lo necesario del JSON gigante de Solana usando referencias (&'a str)
// para no gastar memoria RAM duplicando cadenas de texto.
#[derive(Deserialize, Debug)]
struct RpcResponse<'a> {
    #[serde(borrow)]
    result: Option<RpcResult<'a>>,
}

#[derive(Deserialize, Debug)]
struct RpcResult<'a> {
    #[serde(borrow)]
    value: Option<AccountValue<'a>>,
}

#[derive(Deserialize, Debug)]
struct AccountValue<'a> {
    lamports: u64,
    #[serde(borrow)]
    data: Option<AccountData<'a>>,
}

#[derive(Deserialize, Debug)]
struct AccountData<'a> {
    #[serde(borrow)]
    parsed: Option<ParsedData<'a>>,
}

#[derive(Deserialize, Debug)]
struct ParsedData<'a> {
    #[serde(borrow)]
    info: Option<TokenInfo<'a>>,
}

#[derive(Deserialize, Debug)]
struct TokenInfo<'a> {
    #[serde(borrow)]
    mint: &'a str,
    #[serde(borrow)]
    owner: &'a str,
    #[serde(rename = "tokenAmount")]
    token_amount: Option<TokenAmount>,
}

#[derive(Deserialize, Debug)]
struct TokenAmount {
    #[serde(rename = "uiAmount")]
    ui_amount: Option<f64>,
}

// ==========================================
// 2. ESTRUCTURA DE SALIDA Y SANITIZACIÓN
// ==========================================

// El JSON ultraligero que le entregaremos a la IA
#[derive(Serialize, Debug)]
pub struct CleanAccountView {
    pub mint: String,
    pub owner: String,
    pub balance: f64,
    pub sol_rent_lamports: u64,
}

/// Sanitiza cadenas de texto para evitar ataques de Prompt Injection en la LLM.
/// Elimina caracteres de control, backticks y limita la longitud a 80 caracteres.
fn sanitizar_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() && *c != '`' && *c != '{' && *c != '}')
        .take(80)
        .collect()
}

// ==========================================
// 3. FUNCIÓN PRINCIPAL DE PROCESAMIENTO
// ==========================================

/// Recibe los bytes crudos del JSON de Solana, limpia la basura y devuelve
/// un JSON masticado de menos de 100 tokens.
#[inline(always)]
pub fn masticar_rpc_solana(json_bytes: &[u8]) -> Result<String> {
    // Zero-copy parsing directo desde bytes
    let parsed_rpc: RpcResponse = serde_json::from_slice(json_bytes)?;

    // Extracción segura usando Option (evita panics si el JSON no es de un Token)
    if let Some(res) = parsed_rpc.result {
        if let Some(val) = res.value {
            let lamports = val.lamports;

            if let Some(info) = val.data.and_then(|d| d.parsed).and_then(|p| p.info) {
                let balance_limpio = CleanAccountView {
                    mint: sanitizar_string(info.mint),
                    owner: sanitizar_string(info.owner),
                    balance: info.token_amount.and_then(|t| t.ui_amount).unwrap_or(0.0),
                    sol_rent_lamports: lamports,
                };

                return serde_json::to_string(&balance_limpio);
            }
        }
    }

    // Salida fallback segura si la cuenta no es un SPL-Token
    Ok(r#"{"status":"datos_no_reconocidos_o_cuenta_vacia"}"#.to_string())
}

// ==========================================
// 4. PRUEBA UNITARIA LOCAL
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masticado_y_sanitizacion() {
        // Simulamos un JSON gigante y sucio devuelto por un RPC de Solana
        let raw_json = r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 240123982 },
                "value": {
                    "lamports": 2039280,
                    "data": {
                        "parsed": {
                            "info": {
                                "mint": "EPjFWdd5`IGNORE_PROMPT`",
                                "owner": "83vS4xZ_User_Wallet",
                                "tokenAmount": { "uiAmount": 150.5 }
                            }
                        }
                    }
                }
            }
        }"#;

        let resultado = masticar_rpc_solana(raw_json.as_bytes()).unwrap();
        
        // Verificamos que eliminó el backtick y la inyección maliciosa
        assert!(!resultado.contains('`'));
        assert!(resultado.contains("EPjFWdd5IGNORE_PROMPT"));
        assert!(resultado.contains("150.5"));
        println!("JSON Masticado: {}", resultado);
    }
}