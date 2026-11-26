using System.Text;

namespace DesLab;

public sealed class MainForm : Form
{
    private readonly ComboBox operation = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly ComboBox passwordSource = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox password = new() { UseSystemPasswordChar = true };
    private readonly TextBox passwordFile = new() { ReadOnly = true };
    private readonly TextBox input = new() { ReadOnly = true };
    private readonly TextBox output = new() { ReadOnly = true };
    private readonly Button start = new() { Text = "Выполнить", AutoSize = true };
    private readonly Button passwordBrowse = new() { Text = "Выбрать…", AutoSize = true };
    private readonly Label status = new() { AutoSize = true, Text = "Выберите операцию и файлы." };
    private readonly TableLayoutPanel fields = new() { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3 };
    private readonly CancellationTokenSource cancellation = new();
    private readonly ProgressBar progress = new() { Dock = DockStyle.Top, Style = ProgressBarStyle.Marquee, Visible = false };

    public MainForm()
    {
        Text = "Лабораторная №3 — DES-CBC — Вариант 2";
        Font = new Font("Segoe UI", 11);
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = new Size(1000, 740); MinimumSize = new Size(850, 650);
        StartPosition = FormStartPosition.CenterScreen;
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var fileTab = new TabPage("Шифрование и расшифрование") { Padding = new Padding(18), AutoScroll = true };
        var helpTab = new TabPage("Описание DES-CBC") { Padding = new Padding(16), BackColor = Color.White };
        tabs.TabPages.AddRange([fileTab, helpTab]); Controls.Add(tabs);
        var layout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { AutoSize = true, Margin = new Padding(0, 0, 0, 24),
            Text = $"Студент: {Program.Student}\nВариант 2 — DES, режим CBC" });
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        operation.Items.AddRange(["Шифрование", "Расшифрование"]); operation.SelectedIndex = 0;
        passwordSource.Items.AddRange(["С клавиатуры", "Из файла UTF-8"]); passwordSource.SelectedIndex = 0;
        AddRow("Операция", operation);
        AddRow("Источник пароля", passwordSource);
        var show = new CheckBox { Text = "Показать", AutoSize = true };
        show.CheckedChanged += (_, _) => password.UseSystemPasswordChar = !show.Checked;
        AddRow("Пароль", password, show);
        AddRow("Файл пароля", passwordFile, passwordBrowse);
        passwordSource.SelectedIndexChanged += (_, _) => UpdatePasswordMode();
        passwordBrowse.Click += (_, _) => Choose(passwordFile, false);
        var inputBrowse = new Button { Text = "Выбрать…", AutoSize = true };
        var outputBrowse = new Button { Text = "Сохранить в…", AutoSize = true };
        inputBrowse.Click += (_, _) => Choose(input, false);
        outputBrowse.Click += (_, _) => Choose(output, true);
        AddRow("Исходный файл", input, inputBrowse);
        AddRow("Файл назначения", output, outputBrowse);
        layout.Controls.Add(fields);
        layout.Controls.Add(new Label { AutoSize = true, Margin = new Padding(0, 18, 0, 18),
            Text = "Подходит любой формат файла. Для отчета используйте файл от 1024 байт.\n" +
                   "При расшифровании укажите исходное расширение результата, например .docx." });
        start.Click += async (_, _) => await RunOperation();
        layout.Controls.Add(start); layout.Controls.Add(progress); layout.Controls.Add(status);
        fileTab.Controls.Add(layout);
        helpTab.Controls.Add(new TextBox { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill,
            BorderStyle = BorderStyle.None, BackColor = Color.White, Font = new Font("Segoe UI", 12),
            ScrollBars = ScrollBars.Vertical, WordWrap = true,
            Text = HelpText.ReplaceLineEndings(Environment.NewLine) });
        UpdatePasswordMode();
        FormClosing += (_, _) => cancellation.Cancel();
    }

    private void AddRow(string caption, Control control, Control? button = null)
    {
        int row = fields.RowCount++;
        fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        fields.Controls.Add(new Label { Text = caption, AutoSize = true, Anchor = AnchorStyles.Left,
            Margin = new Padding(0, 10, 8, 10) }, 0, row);
        control.Dock = DockStyle.Fill; control.Margin = new Padding(0, 8, 8, 8);
        fields.Controls.Add(control, 1, row);
        if (button is not null) fields.Controls.Add(button, 2, row);
    }

    private void UpdatePasswordMode()
    {
        password.Enabled = passwordSource.SelectedIndex == 0;
        passwordFile.Enabled = passwordBrowse.Enabled = !password.Enabled;
    }

    private void Choose(TextBox target, bool save)
    {
        using FileDialog dialog = save
            ? new SaveFileDialog { OverwritePrompt = false, FileName = operation.SelectedIndex == 0 ? "result.des" : "restored.bin" }
            : new OpenFileDialog { CheckFileExists = true };
        dialog.Filter = "Все файлы (*.*)|*.*";
        if (dialog.ShowDialog(this) == DialogResult.OK) target.Text = dialog.FileName;
    }

    private async Task RunOperation()
    {
        try
        {
            if (input.Text.Length == 0 || output.Text.Length == 0)
                throw new ArgumentException("Выберите исходный файл и файл назначения.");
            string text = passwordSource.SelectedIndex == 0 ? password.Text : FileCipher.ReadPassword(passwordFile.Text);
            FileCipher.ValidatePassword(text);
            if (passwordSource.SelectedIndex == 1 && Path.GetFullPath(output.Text).Equals(
                Path.GetFullPath(passwordFile.Text), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Файл назначения не должен совпадать с файлом пароля.");
            if (File.Exists(output.Text) && MessageBox.Show(this, "Заменить выбранный файл назначения?",
                "Сохранение", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            string from = input.Text, to = output.Text;
            bool decrypt = operation.SelectedIndex == 1;
            fields.Enabled = start.Enabled = false; progress.Visible = true;
            status.Text = "Выполняется обработка…";
            long size = await Task.Run(() => FileCipher.Process(from, to, text, decrypt, cancellation.Token));
            if (!IsDisposed) status.Text = $"Готово. Прочитано {size} байт.\nРезультат: {to}";
        }
        catch (OperationCanceledException) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            if (!IsDisposed) { status.Text = "Результат не сохранен."; MessageBox.Show(this, error.Message, "Ошибка"); }
        }
        finally
        {
            if (!IsDisposed) { fields.Enabled = start.Enabled = true; progress.Visible = false; }
        }
    }

    private const string HelpText = """
        DES В РЕЖИМЕ CBC

        DES — симметричный блочный шифр. Блок: 8 байт (64 бита).
        Ключ: 56 значащих бит; еще 8 бит служат для контроля четности.
        Один блок проходит начальную перестановку, 16 раундов Фейстеля
        и конечную перестановку. Раундовые ключи имеют длину 48 бит.

        ЦЕПОЧКА БЛОКОВ CBC

        Шифрование: C[i] = DES(K, P[i] XOR C[i-1]), C[0] = IV.
        Расшифрование: P[i] = DES^-1(K, C[i]) XOR C[i-1].
        При каждом шифровании создается случайный IV длиной 8 байт.
        Он сохраняется в начале результата; отдельно вводить IV не нужно.

        ПАРОЛЬ И ФАЙЛЫ

        Выберите операцию, источник пароля, исходный файл и файл назначения.
        Пароль из файла: одна строка UTF-8, до 4 КБ. BOM и один завершающий
        перевод строки не учитываются; пробелы являются частью пароля.
        Учебное получение ключа: первые 8 байт SHA-256 от UTF-8 пароля,
        затем установка нечетной четности. DES и CBC реализованы вручную.

        Файл результата: 8 байт IV, затем зашифрованные блоки.
        PKCS#7 добавляет от 1 до 8 байт; каждый равен их количеству.
        При расшифровании дополнение проверяется и удаляется.
        Имя и расширение исходного файла не сохраняются. Выберите их сами.

        """;
}
