namespace DesLab;

internal static class Program
{
    public const string Student = "Буслаев Роман Витальевич";
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
