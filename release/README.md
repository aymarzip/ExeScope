# ExeScope Pre-built Release Binaries

Скомпилированные исполняемые файлы для Windows x64.

## Состав

- **ExeScope.GUI.exe**: кроссплатформенный графический интерфейс на Avalonia UI 11 (.NET 8).
- **ExeScope.Agent.Windows.exe**: низкоуровневый агент перехвата ETW и хуков с gRPC/IPC каналом.
- **ExeScope.TestTarget.exe**: тестовый образец для проверки всех источников телеметрии (файлы, дочерние процессы, реестр, локальная сеть, инъекции).

## Контрольные суммы (SHA-256)

| Файл | SHA-256 |
| :--- | :--- |
| ExeScope.GUI.exe | 30571D5050672720D06855547EB587CADCFEA750703F125BAC2B9F1D20CC53C5 |
| ExeScope.Agent.Windows.exe | 10AC9C77B7009EE76391DA33E5C50F9A480073E63FBBA367B78AA5F9DFA4B133 |
| ExeScope.TestTarget.exe | F03442EE30EB49BC02EF59B10BCEA1C6C4D4534085F6297E91137AE1AD511A16 |

## Требования для запуска

- Windows 10 (1809+) или Windows 11 (x64)
- Установленный .NET Desktop Runtime 8.0
