using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DesLab;

string root = Path.GetFullPath(args.Single());
string work = Path.Combine(root, "evidence", "check-files");
Directory.CreateDirectory(work);
void Check(bool ok, string message) { if (!ok) throw new Exception(message); }
byte[] Block(ulong value) { byte[] b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
const ulong key64 = 0x133457799bbcdff1, plain64 = 0x0123456789abcdef;
var des = new DesAlgorithm(key64);
var trace = new List<DesRound>();
ulong cipher64 = des.Transform(plain64, trace: trace);
Check(cipher64 == 0x85e813540f0ab405, "Known DES vector");
Check(des.Transform(cipher64, true) == plain64, "Known vector decryption");
Check(trace[0].Key == 0x1b02effc7072 && trace[0].Expanded == 0x7a15557a1555 &&
    trace[0].Mixed == 0x6117ba866527 && trace[0].Substituted == 0x5c82b597 &&
    trace[0].Function == 0x234aa9bb && trace[0].Left == 0xf0aaf0aa &&
    trace[0].Right == 0xef4a6544, "First-round calculation");
using var oracle = DES.Create(); oracle.Key = Block(key64);
for (int i = 0; i < 128; i++)
{
    byte[] block = RandomNumberGenerator.GetBytes(8);
    byte[] expected = oracle.EncryptEcb(block, PaddingMode.None);
    ulong actual = des.Transform(BinaryPrimitives.ReadUInt64BigEndian(block));
    Check(Block(actual).SequenceEqual(expected), "Random DES block");
    Check(Block(des.Transform(actual, true)).SequenceEqual(block), "Random inverse");
}
const string password = "Roman-Lab3-2026";
var files = Directory.GetFiles(Path.Combine(root, "samples"))
    .Where(x => !Path.GetFileName(x).StartsWith("password")).ToList();
foreach (int size in new[] {0,1,7,8,9,15,16,17,1023,1024,1025})
{
    string file = Path.Combine(work, $"boundary-{size}.bin");
    File.WriteAllBytes(file, Enumerable.Range(0,size).Select(i => (byte)(i*37)).ToArray());
    files.Add(file);
}
var results = new List<object>();
foreach (string file in files)
{
    string encoded = Path.Combine(work, Path.GetFileName(file)+".des");
    string decoded = encoded+".restored";
    FileCipher.Process(file, encoded, password, false);
    FileCipher.Process(encoded, decoded, password, true);
    byte[] original = File.ReadAllBytes(file), container = File.ReadAllBytes(encoded);
    Check(original.SequenceEqual(File.ReadAllBytes(decoded)), "Round-trip: "+file);
    oracle.Key = FileCipher.PasswordKey(password);
    byte[] expected = oracle.EncryptCbc(original, container[..8], PaddingMode.PKCS7);
    Check(expected.SequenceEqual(container[8..]), "CBC reference: "+file);
    Check(container.Length == 8 + (original.Length/8+1)*8, "Container length");
    results.Add(new { file=Path.GetFileName(file), bytes=original.Length,
        encrypted_bytes=container.Length, restored_exactly=true, matches_library_des_cbc=true });
}
string passwordPath=Path.Combine(root,"samples","password.txt");
Check(FileCipher.ReadPassword(passwordPath)==password,"Password file");
foreach (string ending in new[] {"","\n","\r\n"})
{
    string path=Path.Combine(work,"password-bom.txt");
    File.WriteAllText(path," пароль с пробелами "+ending,new UTF8Encoding(true));
    Check(FileCipher.ReadPassword(path)==" пароль с пробелами ","UTF-8 BOM/newline/spaces");
}
string sample=files[0], encrypted=Path.Combine(work,"iv-test.des"), second=encrypted+".second";
FileCipher.Process(sample,encrypted,password,false); FileCipher.Process(sample,second,password,false);
Check(!File.ReadAllBytes(encrypted)[..8].SequenceEqual(File.ReadAllBytes(second)[..8]),"Fresh IV");
byte[] broken=File.ReadAllBytes(encrypted);
int padding=8-(int)(new FileInfo(sample).Length%8);
broken[^9]^=(byte)padding; // Последний расшифрованный байт становится 00.
string invalid=Path.Combine(work,"invalid.des"), sentinel=Path.Combine(work,"destination.txt");
File.WriteAllBytes(invalid,broken); File.WriteAllText(sentinel,"unchanged");
bool rejected=false;
try {FileCipher.Process(invalid,sentinel,password,true);} catch(InvalidDataException) {rejected=true;}
Check(rejected && File.ReadAllText(sentinel)=="unchanged","Invalid padding preserves destination");
foreach (int size in new[] {0,8,15,17})
{
    File.WriteAllBytes(invalid,new byte[size]); rejected=false;
    try {FileCipher.Process(invalid,sentinel,password,true);} catch(InvalidDataException) {rejected=true;}
    Check(rejected && File.ReadAllText(sentinel)=="unchanged","Invalid size");
}
rejected=false;
try {FileCipher.Process(sentinel,sentinel,password,false);} catch(ArgumentException) {rejected=true;}
Check(rejected && File.ReadAllText(sentinel)=="unchanged","Same path");
using(var cancelled=new CancellationTokenSource())
{
    cancelled.Cancel(); rejected=false;
    try {FileCipher.Process(sample,sentinel,password,false,cancelled.Token);} catch(OperationCanceledException) {rejected=true;}
    Check(rejected && File.ReadAllText(sentinel)=="unchanged","Cancellation");
}
Check(!Directory.GetFiles(work,".des-*.tmp").Any(),"No temporary leftovers");
var report=new { timestamp=DateTimeOffset.Now, known_vector=true, random_blocks=128,
    first_round_matches=true, files=results, fresh_iv=true, password_file=true,
    invalid_padding_preserves_output=true, invalid_size_rejected=true,
    same_path_rejected=true, cancellation_preserves_output=true, gui_tested=false };
File.WriteAllText(Path.Combine(root,"evidence","checks.json"),
    JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true}));
File.WriteAllText(Path.Combine(root,"evidence","rounds.json"),
    JsonSerializer.Serialize(trace,new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS: known DES vector, 128 blocks, {files.Count} CBC files, first round, password and error handling.");
