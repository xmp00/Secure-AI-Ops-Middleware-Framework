import re
import argparse
import sys
import os

class LogSanitizer:
    def __init__(self, custom_keywords=None):
        # Статистика для отчета
        self.stats = {
            "ips_removed": 0,
            "emails_removed": 0,
            "users_redacted": 0,
            "keywords_redacted": 0
        }

        # 1. Regex паттерны для PII (Personal Identifiable Information)
        self.patterns = {
            # IPv4: ищет 4 группы цифр через точку
            "ips_removed": (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_REDACTED]'),
            
            # Email: стандартный паттерн
            "emails_removed": (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
            
            # MAC адреса (часто встречаются в логах инфраструктуры)
            "macs_removed": (r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', '[MAC_REDACTED]')
        }
        
        # 2. Специфичные ключевые слова (чувствительные данные проекта)
        # Если передали список — используем его, иначе дефолтный (для теста)
        self.sensitive_keywords = custom_keywords if custom_keywords else [
            "epo-prod", "admin-secret", "db_password", "internal-vlan"
        ]

    def sanitize_line(self, line):
        """Обрабатывает одну строку лога"""
        clean_line = line
        
        # Проход по Regex паттернам
        for stat_key, (pattern, placeholder) in self.patterns.items():
            # Считаем количество совпадений перед заменой
            matches = len(re.findall(pattern, clean_line))
            if matches > 0:
                self.stats[stat_key] = self.stats.get(stat_key, 0) + matches
                clean_line = re.sub(pattern, placeholder, clean_line)
        
        # Проход по ключевым словам (Case Insensitive)
        for keyword in self.sensitive_keywords:
            if keyword.lower() in clean_line.lower():
                # Считаем вхождения
                count = clean_line.lower().count(keyword.lower())
                self.stats["keywords_redacted"] += count
                
                # Заменяем (экранируем спецсимволы в keyword на всякий случай)
                clean_line = re.sub(r'(?i)' + re.escape(keyword), '[INTERNAL_SECRET]', clean_line)
                
        return clean_line

    def process_file(self, input_path, output_path):
        if not os.path.exists(input_path):
            print(f"❌ Error: Input file '{input_path}' not found.")
            return False

        try:
            with open(input_path, 'r', encoding='utf-8', errors='replace') as f_in, \
                 open(output_path, 'w', encoding='utf-8') as f_out:
                
                print(f"🔄 Processing {input_path}...")
                
                for line in f_in:
                    safe_line = self.sanitize_line(line)
                    f_out.write(safe_line)
            
            return True
            
        except Exception as e:
            print(f"❌ Critical Error: {e}")
            return False

    def print_stats(self):
        print("\n📊 Sanitization Report:")
        print("-" * 30)
        for key, value in self.stats.items():
            if value > 0:
                print(f"   ✅ {key.replace('_', ' ').title()}: {value}")
        print("-" * 30)

if __name__ == "__main__":
    # Настройка аргументов командной строки (как у взрослых утилит)
    parser = argparse.ArgumentParser(description="Secure AI-Ops Log Sanitizer")
    parser.add_argument("input_file", help="Path to the raw log file")
    parser.add_argument("--output", help="Path to save sanitized log", default=None)
    
    args = parser.parse_args()
    
    # Если output не задан, добавляем .clean к имени файла
    output_file = args.output if args.output else args.input_file + ".clean"

    sanitizer = LogSanitizer()
    success = sanitizer.process_file(args.input_file, output_file)
    
    if success:
        sanitizer.print_stats()
        print(f"💾 Saved to: {output_file}")
    else:
        sys.exit(1)
