import re
import sys

class LogSanitizer:
    def __init__(self):
        # 1. Определяем паттерны для вырезания (Regex)
        self.patterns = {
            # IPv4 адреса (защита инфраструктуры)
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b': '[IP_REDACTED]',
            
            # Email адреса (защита PII - персональных данных)
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[EMAIL_REDACTED]',
            
            # Внутренние ID пользователей (пример: user_12345 или uid=500)
            r'\b(user_id|uid)[=:]?\s*\d+\b': '[USER_ID_REDACTED]',
            
            # MAC адреса
            r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})': '[MAC_REDACTED]'
        }
        
        # 2. Список чувствительных слов (Специфика клиента, например EPO)
        # Эти слова заменяются на [INTERNAL_HOST]
        self.sensitive_keywords = [
            "epo-prod", "opentext-admin", "admin-console", 
            "internal-db", "secret-key", "eu-zone-01"
        ]

    def sanitize_text(self, text):
        """Проходит по тексту и заменяет чувствительные данные."""
        cleaned_text = text
        
        # Шаг 1: Regex замены
        for pattern, placeholder in self.patterns.items():
            cleaned_text = re.sub(pattern, placeholder, cleaned_text)
            
        # Шаг 2: Замена ключевых слов (Hostnames / Project names)
        for keyword in self.sensitive_keywords:
            # (?i) делает поиск регистронезависимым
            cleaned_text = re.sub(r'(?i)' + re.escape(keyword), '[INTERNAL_ASSET]', cleaned_text)
            
        return cleaned_text

    def process_file(self, input_file, output_file):
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f_in:
                content = f_in.read()
                
            safe_content = self.sanitize_text(content)
            
            with open(output_file, 'w', encoding='utf-8') as f_out:
                f_out.write(safe_content)
                
            print(f"✅ Success. Cleaned log saved to: {output_file}")
            print(f"🔒 Sensitive data removed. Ready for LLM analysis.")
            
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    # Простой запуск: python log_sanitizer.py error.log
    if len(sys.argv) < 2:
        print("Usage: python log_sanitizer.py <logfile>")
        sys.exit(1)
        
    input_log = sys.argv[1]
    output_log = input_log + ".clean.txt"
    
    sanitizer = LogSanitizer()
    sanitizer.process_file(input_log, output_log)
