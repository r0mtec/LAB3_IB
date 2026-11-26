using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace DesLab;

public static class FileCipher
{
    public static string ReadPassword(string path)
    {
        using var file = File.OpenRead(path);
        if (file.Length > 4096) throw new ArgumentException("Файл пароля должен быть не больше 4 КБ.");
        byte[] data = new byte[(int)file.Length];
        file.ReadExactly(data);
        int start = data.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
        string text = new UTF8Encoding(false, true).GetString(data, start, data.Length - start);
        // Убираем только один завершающий перевод строки. Пробелы сохраняем.
        if (text.EndsWith("\r\n")) text = text[..^2];
        else if (text.EndsWith('\n') || text.EndsWith('\r')) text = text[..^1];
        ValidatePassword(text);
        return text;
    }

    public static void ValidatePassword(string text)
    {
        if (text.Length == 0 || text.Contains('\r') || text.Contains('\n'))
            throw new ArgumentException("Пароль должен быть непустой строкой без переводов строки.");
    }

    public static byte[] PasswordKey(string password)
    {
        ValidatePassword(password);
        // Учебное правило получения ключа: первые 8 байт SHA-256 от UTF-8.
        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(password))[..8];
        for (int i = 0; i < 8; i++)
        {
            int top = key[i] & 0xfe;
            key[i] = (byte)(top | ((BitOperations.PopCount((uint)top) & 1) ^ 1));
        }
        return key; // В каждом байте нечетное количество единиц.
    }

    public static long Process(string inputPath, string outputPath, string password,
        bool decrypt, CancellationToken cancellation = default)
    {
        string input = Path.GetFullPath(inputPath), output = Path.GetFullPath(outputPath);
        if (input.Equals(output, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Исходный файл и файл назначения должны быть разными.");
        byte[] key = PasswordKey(password);
        var des = new DesAlgorithm(BinaryPrimitives.ReadUInt64BigEndian(key));
        // Готовый результат заменяет назначение только после успешной обработки.
        string temporary = Path.Combine(Path.GetDirectoryName(output)!, ".des-" + Guid.NewGuid() + ".tmp");
        try
        {
            long size;
            using (var source = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var destination = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write))
            {
                size = source.Length;
                if (decrypt) Decrypt(source, destination, des, cancellation);
                else Encrypt(source, destination, des, cancellation);
                destination.Flush(true);
            }
            cancellation.ThrowIfCancellationRequested();
            File.Move(temporary, output, overwrite: true);
            return size;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    // Формат результата: 8 байт IV, затем DES-CBC с дополнением PKCS#7.
    private static void Encrypt(Stream input, Stream output, DesAlgorithm des, CancellationToken token)
    {
        byte[] buffer = new byte[8];
        byte[] iv = RandomNumberGenerator.GetBytes(8);
        output.Write(iv);
        ulong previous = BinaryPrimitives.ReadUInt64BigEndian(iv);
        while (true)
        {
            token.ThrowIfCancellationRequested();
            int count = ReadBlock(input, buffer);
            if (count < 8) Array.Fill(buffer, (byte)(8 - count), count, 8 - count);
            ulong plain = BinaryPrimitives.ReadUInt64BigEndian(buffer);
            previous = des.Transform(plain ^ previous);
            BinaryPrimitives.WriteUInt64BigEndian(buffer, previous);
            output.Write(buffer);
            if (count < 8) break; // При кратной 8 длине добавится полный блок 08.
        }
    }

    private static void Decrypt(Stream input, Stream output, DesAlgorithm des, CancellationToken token)
    {
        if (input.Length < 16 || input.Length % 8 != 0)
            throw new InvalidDataException("Нужны IV (8 байт) и непустой шифротекст, кратный 8 байтам.");
        byte[] buffer = new byte[8];
        input.ReadExactly(buffer);
        ulong previous = BinaryPrimitives.ReadUInt64BigEndian(buffer);
        while (input.Position < input.Length)
        {
            token.ThrowIfCancellationRequested();
            input.ReadExactly(buffer);
            ulong cipher = BinaryPrimitives.ReadUInt64BigEndian(buffer);
            ulong plain = des.Transform(cipher, decrypt: true) ^ previous;
            previous = cipher; // Нужен исходный шифроблок, а не расшифрованный.
            BinaryPrimitives.WriteUInt64BigEndian(buffer, plain);
            int count = 8;
            if (input.Position == input.Length)
            {
                int pad = buffer[7];
                if (pad < 1 || pad > 8) throw PaddingError();
                for (int i = 8 - pad; i < 8; i++)
                    if (buffer[i] != pad) throw PaddingError();
                count -= pad;
            }
            output.Write(buffer, 0, count);
        }
    }

    private static int ReadBlock(Stream input, byte[] buffer)
    {
        int count = 0;
        while (count < 8)
        {
            int read = input.Read(buffer, count, 8 - count);
            if (read == 0) break;
            count += read;
        }
        return count;
    }

    private static InvalidDataException PaddingError() =>
        new("Неверное дополнение: возможны другой пароль или повреждение файла.");
}
