namespace ExeScope.Engine.Session;

public enum AnalysisSessionState
{
    Ready,              // Готов
    WaitingForLaunch,   // Ожидание
    Recording,          // Запись
    Completed,          // Завершено
    Error               // Ошибка
}
