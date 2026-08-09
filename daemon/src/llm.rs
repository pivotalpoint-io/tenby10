use crate::config::AgentConfig;
use reqwest::blocking::Client;
use serde_json::Value;

pub trait LlmProvider {
    fn evaluate_slot(
        &self,
        system_prompt: &str,
        activity_text: &str,
    ) -> Result<(u32, String), String>;
}

pub struct OpenAiProvider {
    api_key: String,
    client: Client,
}

impl LlmProvider for OpenAiProvider {
    fn evaluate_slot(
        &self,
        system_prompt: &str,
        activity_text: &str,
    ) -> Result<(u32, String), String> {
        let payload = serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user", "content": format!("Activity log:\n{}", activity_text) }
            ],
            "response_format": { "type": "json_object" }
        });

        let res = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .map_err(|e| e.to_string())?;

        let json = res.json::<Value>().map_err(|e| e.to_string())?;

        if let Some(content) = json["choices"][0]["message"]["content"].as_str() {
            let parsed_res = serde_json::from_str::<Value>(content);
            if let Ok(parsed) = parsed_res {
                let score = parsed["score"].as_u64().unwrap_or(0) as u32;
                let reasoning = parsed["reasoning"].as_str().unwrap_or("").to_string();
                return Ok((score, reasoning));
            }
        }

        Err("Failed to parse OpenAI response".into())
    }
}

pub struct AnthropicProvider {
    api_key: String,
    client: Client,
}

impl LlmProvider for AnthropicProvider {
    fn evaluate_slot(
        &self,
        system_prompt: &str,
        activity_text: &str,
    ) -> Result<(u32, String), String> {
        let payload = serde_json::json!({
            "model": "claude-3-5-sonnet-20240620",
            "max_tokens": 512,
            "system": system_prompt,
            "messages": [
                { "role": "user", "content": format!("Activity log:\n{}", activity_text) }
            ]
        });

        let res = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&payload)
            .send()
            .map_err(|e| e.to_string())?;

        let json = res.json::<Value>().map_err(|e| e.to_string())?;

        if let Some(content) = json["content"][0]["text"].as_str() {
            let clean_content = content
                .trim()
                .strip_prefix("```json")
                .unwrap_or(content)
                .strip_suffix("```")
                .unwrap_or(content)
                .trim();

            if let Ok(parsed) = serde_json::from_str::<Value>(clean_content) {
                let score = parsed["score"].as_u64().unwrap_or(0) as u32;
                let reasoning = parsed["reasoning"].as_str().unwrap_or("").to_string();
                return Ok((score, reasoning));
            }
        }

        Err("Failed to parse Anthropic response".into())
    }
}

pub struct GeminiProvider {
    api_key: String,
    client: Client,
}

impl LlmProvider for GeminiProvider {
    fn evaluate_slot(
        &self,
        system_prompt: &str,
        activity_text: &str,
    ) -> Result<(u32, String), String> {
        let payload = serde_json::json!({
            "systemInstruction": {
                "parts": [{ "text": system_prompt }]
            },
            "contents": [{
                "parts": [{ "text": format!("Activity log:\n{}", activity_text) }]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        });

        let res = self
            .client
            .post("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent")
            // The key rides a header, not the query string: URLs land in proxy
            // and gateway logs.
            .header("x-goog-api-key", &self.api_key)
            .json(&payload)
            .send()
            .map_err(|e| e.to_string())?;

        let json = res.json::<Value>().map_err(|e| e.to_string())?;

        if let Some(content) = json["candidates"][0]["content"]["parts"][0]["text"].as_str() {
            let parsed_res = serde_json::from_str::<Value>(content);
            if let Ok(parsed) = parsed_res {
                let score = parsed["score"].as_u64().unwrap_or(0) as u32;
                let reasoning = parsed["reasoning"].as_str().unwrap_or("").to_string();
                return Ok((score, reasoning));
            }
        }

        Err("Failed to parse Gemini response".into())
    }
}

pub fn get_llm_provider(config: &AgentConfig) -> Option<Box<dyn LlmProvider>> {
    if config.llm_api_key.is_empty() || config.llm_provider.is_empty() {
        return None;
    }

    let client = Client::new();
    let api_key = config.llm_api_key.clone();

    match config.llm_provider.to_lowercase().as_str() {
        "openai" => Some(Box::new(OpenAiProvider { api_key, client })),
        "gemini" => Some(Box::new(GeminiProvider { api_key, client })),
        "anthropic" => Some(Box::new(AnthropicProvider { api_key, client })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;

    #[test]
    fn test_get_llm_provider_empty_config() {
        let mut config = AgentConfig::default();

        // Both empty
        assert!(get_llm_provider(&config).is_none());

        // API key missing
        config.llm_provider = "openai".to_string();
        assert!(get_llm_provider(&config).is_none());

        // Provider missing
        config.llm_provider = "".to_string();
        config.llm_api_key = "test_key".to_string();
        assert!(get_llm_provider(&config).is_none());
    }

    #[test]
    fn test_get_llm_provider_instantiation() {
        let mut config = AgentConfig::default();
        config.llm_api_key = "test_key".to_string();

        config.llm_provider = "openai".to_string();
        assert!(get_llm_provider(&config).is_some());

        config.llm_provider = "anthropic".to_string();
        assert!(get_llm_provider(&config).is_some());

        config.llm_provider = "gemini".to_string();
        assert!(get_llm_provider(&config).is_some());

        config.llm_provider = "unknown".to_string();
        assert!(get_llm_provider(&config).is_none());
    }
}
