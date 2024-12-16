import os
import sys
import logging
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import getpass
from logging.handlers import RotatingFileHandler
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Убедитесь, что у вас есть config.py с EMAIL и PASSWORD (пароль приложения)
from config import EMAIL, PASSWORD

class FileAuditHandler(FileSystemEventHandler):
    def __init__(self, logger, log_file):
        super().__init__()
        self.logger = logger
        self.log_file = log_file  # Имя лог-файла для игнорирования

    def on_created(self, event):
        if event.is_directory:
            self.log_event("создана", event, is_directory=True)
        elif os.path.basename(event.src_path) != self.log_file:
            self.log_event("создан", event, is_directory=False)

    def on_deleted(self, event):
        if event.is_directory:
            self.log_event("удалена", event, is_directory=True)
        elif os.path.basename(event.src_path) != self.log_file:
            self.log_event("удалён", event, is_directory=False)

    def on_modified(self, event):
        # Игнорируем изменения в лог-файле
        if not event.is_directory and os.path.basename(event.src_path) != self.log_file:
            self.log_event("изменён", event, is_directory=False)

    def on_moved(self, event):
        if event.is_directory:
            self.log_event("перемещена", event, dest_path=event.dest_path, is_directory=True)
        elif os.path.basename(event.src_path) != self.log_file:
            self.log_event("перемещён", event, dest_path=event.dest_path, is_directory=False)

    def log_event(self, action, event, dest_path=None, is_directory=False):
        user = getpass.getuser()
        entity_type = "Папка" if is_directory else "Файл"
        if dest_path:
            message = f"{user} - {entity_type} {action}: {event.src_path} → {dest_path}"
        else:
            message = f"{user} - {entity_type} {action}: {event.src_path}"
        self.logger.info(message)

# Настройка логгера с ротацией
def setup_logger(log_file, name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

# Генерация статистики и графиков
def generate_statistics(log_file):
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        print(f"Файл {log_file} пуст или не существует. Невозможно построить график.")
        return

    event_counts = defaultdict(int)
    with open(log_file, "r") as f:
        for line in f:
            parts = line.split(" - ")
            if len(parts) > 2:
                event = parts[2].split(":")[0].strip()
                event_counts[event] += 1

    if not event_counts:
        print("Нет данных для построения графика.")
        return

    plt.figure(figsize=(10, 6))
    plt.bar(event_counts.keys(), event_counts.values(), color='skyblue')
    plt.xlabel("Тип события", fontsize=12)
    plt.ylabel("Количество", fontsize=12)
    plt.title("Статистика событий", fontsize=14)
    plt.xticks(rotation=45, fontsize=10)
    plt.tight_layout()
    plt.savefig("event_statistics.png")
    plt.close()

# Генерация текстового отчета
def generate_text_report(log_file, output_file="text_report.txt"):
    """
    Генерирует текстовый отчет на основе данных из лог-файла.
    :param log_file: Путь к лог-файлу
    :param output_file: Имя файла для сохранения текстового отчета
    """
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        print(f"Файл {log_file} пуст или не существует. Невозможно создать текстовый отчет.")
        return

    event_counts = defaultdict(int)
    events = []

    with open(log_file, "r") as f:
        for line in f:
            parts = line.split(" - ")
            if len(parts) > 2:
                event = parts[2].split(":")[0].strip()
                event_counts[event] += 1
                events.append(line.strip())

    with open(output_file, "w", encoding="utf-8") as report:
        report.write("Текстовый отчет по журналу событий\n")
        report.write("=" * 40 + "\n")
        report.write(f"Дата создания отчета: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write("\n")

        # Общая статистика
        report.write("Статистика событий:\n")
        for event, count in event_counts.items():
            report.write(f"{event}: {count}\n")
        report.write("\n")

        # Детализированная информация о событиях
        report.write("Детализированная информация о событиях:\n")
        for event in events:
            report.write(f"{event}\n")

    print(f"Текстовый отчет создан: {output_file}")

# Функция для отправки email с отчётом
def send_email_with_attachments(
        smtp_server="smtp.yandex.ru",
        smtp_port=465,  # Используйте 465 для SSL
        email_sender=EMAIL,
        email_recipient=EMAIL,
        email_password=PASSWORD,
        subject="Отчет по журналу событий",
        body="Вложенные файлы из указанной директории.",
        files=["event_statistics.png", "file_system_log.txt", "text_report.txt"]
    ):
    """
    Отправляет письмо самому себе с прикрепленными файлами из указанной директории.

    :param smtp_server: Адрес SMTP сервера
    :param smtp_port: Порт SMTP сервера
    :param email_sender: Ваш адрес электронной почты
    :param email_recipient: Адрес получателя
    :param email_password: Пароль от почты (или пароль приложения)
    :param subject: Тема письма
    :param body: Текст сообщения
    :param files: Список файлов для прикрепления
    """
    # Создание сообщения
    msg = MIMEMultipart()
    msg['From'] = email_sender
    msg['To'] = email_recipient  # Отправляем самому себе
    msg['Subject'] = subject

    # Добавление тела письма
    msg.attach(MIMEText(body, 'plain'))

    # Добавление файлов
    for filename in files:
        file_path = os.path.join(".", filename)
        if os.path.isfile(file_path):  # Проверяем, что это файл
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f"attachment; filename={filename}")
                msg.attach(part)
        else:
            print(f"Файл {filename} не найден.")

    # Инициализация сервера перед блоком try
    server = None

    # Отправка письма через SMTP сервер
    try:
        # Используем SSL для Yandex
        server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
        server.login(email_sender, email_password)
        server.sendmail(email_sender, email_recipient, msg.as_string())
        print("Сообщение отправлено!")
    except smtplib.SMTPException as e:
        print(f"Ошибка SMTP: {e}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"Ошибка аутентификации: {e}")
    except smtplib.SMTPServerDisconnected as e:
        print(f"Сервер отключил соединение: {e}")
    except Exception as e:
        print(f"Неизвестная ошибка: {e}")
    finally:
        if server:
            server.quit()

class AuditGUI:
    def __init__(self, root, log_file):
        self.root = root
        self.root.title("Системный аудит")
        self.root.geometry("800x600")
        self.log_file = log_file

        # Фильтры
        self.filter_frame = tk.Frame(root)
        self.filter_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        self.user_label = tk.Label(self.filter_frame, text="Пользователь:")
        self.user_label.grid(row=0, column=0)
        self.user_entry = tk.Entry(self.filter_frame)
        self.user_entry.grid(row=0, column=1)

        self.event_label = tk.Label(self.filter_frame, text="Тип события:")
        self.event_label.grid(row=1, column=0)
        self.event_entry = tk.Entry(self.filter_frame)
        self.event_entry.grid(row=1, column=1)

        self.time_label = tk.Label(self.filter_frame, text="Время (ГГГГ-ММ-ДД):")
        self.time_label.grid(row=2, column=0)
        self.time_entry = tk.Entry(self.filter_frame)
        self.time_entry.grid(row=2, column=1)

        self.filter_button = tk.Button(self.filter_frame, text="Применить", command=self.apply_filter)
        self.filter_button.grid(row=3, column=0, columnspan=2)

        # Таблица
        self.tree = ttk.Treeview(root, columns=("Timestamp", "User", "Event"), show="headings")
        self.tree.heading("Timestamp", text="Время")
        self.tree.heading("User", text="Пользователь")
        self.tree.heading("Event", text="Событие")
        self.tree.column("Timestamp", width=150)
        self.tree.column("User", width=150)
        self.tree.column("Event", width=500)
        self.tree.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        self.report_button = tk.Button(root, text="Создать отчёт", command=self.create_report)
        self.report_button.grid(row=2, column=0, padx=5, pady=5)

        self.refresh_button = tk.Button(root, text="Обновить", command=self.load_logs)
        self.refresh_button.grid(row=2, column=1, padx=5, pady=5)

        self.send_email_button = tk.Button(root, text="Отправить отчёт по email", command=self.send_report_email)
        self.send_email_button.grid(row=2, column=2, padx=5, pady=5)

        self.text_report_button = tk.Button(root, text="Создать текстовый отчёт", command=self.create_text_report)
        self.text_report_button.grid(row=3, column=0, padx=5, pady=5)

        # Загрузка логов
        self.load_logs()

    def load_logs(self):
        self.tree.delete(*self.tree.get_children())
        with open(self.log_file, "r") as f:
            for line in f:
                parts = line.split(" - ")
                if len(parts) >= 3:
                    timestamp = parts[0]
                    user = parts[1]
                    event = " - ".join(parts[2:]).strip()
                    self.tree.insert("", "end", values=(timestamp, user, event))

    def apply_filter(self):
        user_filter = self.user_entry.get().lower()
        event_filter = self.event_entry.get().lower()
        time_filter = self.time_entry.get()

        self.tree.delete(*self.tree.get_children())
        with open(self.log_file, "r") as f:
            for line in f:
                parts = line.split(" - ")
                if len(parts) >= 3:
                    timestamp = parts[0]
                    user = parts[1]
                    event = " - ".join(parts[2:]).strip()
                    if (not user_filter or user_filter in user.lower()) and \
                       (not event_filter or event_filter in event.lower()) and \
                       (not time_filter or time_filter in timestamp):
                        self.tree.insert("", "end", values=(timestamp, user, event))

    def create_report(self):
        generate_statistics(self.log_file)
        messagebox.showinfo("Отчёт", "Статистика событий создана: event_statistics.png")

    def create_text_report(self):
        generate_text_report(self.log_file)
        messagebox.showinfo("Отчёт", "Текстовый отчет создан: text_report.txt")

    def send_report_email(self):
        # Отправка email в отдельном потоке
        email_thread = threading.Thread(target=self._send_email_thread, daemon=True)
        email_thread.start()

    def _send_email_thread(self):
        try:
            send_email_with_attachments(
                smtp_server="smtp.yandex.ru",
                smtp_port=465,  # Используйте 465 для SSL
                email_sender=EMAIL,
                email_recipient=EMAIL,
                email_password=PASSWORD,
                subject="Отчет по журналу событий",
                body="Вложенные файлы из указанной директории.",
                files=["event_statistics.png", "file_system_log.txt", "text_report.txt"]
            )
            messagebox.showinfo("Отчёт", "Отчёт успешно отправлен по email.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при отправке письма: {e}")

def main():
    if len(sys.argv) < 2:
        print("Использование: python3 audit_tool.py <путь_к_папке>")
        sys.exit(1)

    path = sys.argv[1]

    if not os.path.exists(path) or not os.path.isdir(path):
        print(f"Ошибка: Указанный путь '{path}' не существует или не является папкой.")
        sys.exit(1)

    log_file = "file_system_log.txt"
    file_logger = setup_logger(log_file, "FileSystem")
    file_logger.info(f"Запуск мониторинга папки: {path}")

    event_handler = FileAuditHandler(file_logger, log_file)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    # Запуск наблюдателя в отдельном потоке
    observer_thread = threading.Thread(target=observer.start, daemon=True)
    observer_thread.start()
    # Запуск графического интерфейса
    root = tk.Tk()
    gui = AuditGUI(root, log_file)

    # Остановка наблюдателя при закрытии окна и очистка лога
    def on_closing():
        observer.stop()
        observer.join()

        # Очищаем лог-файл
        with open(log_file, "w") as f:
            f.write("")

        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
    
if __name__ == "__main__":
    main()
