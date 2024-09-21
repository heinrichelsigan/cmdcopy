using System.Reflection;
using System.IO;
using Microsoft.Win32.Api;
using System.Runtime.Intrinsics.X86;

namespace gscopy
{
    /// <summary>
    /// gscopy simple console program, that demonstrates 
    /// File.Copy, File.Move, Win32 Api kernel32.dll File.XCopy or File.Write.
    /// <see cref="NativeWrapper.XCopy(string, string)">xcopy</see> switch uses 
    /// <seealso href="https://github.com/heinrichelsigan/cmdcopy/blob/master/gscopy/InternalWrapper.cs">
    /// Win32.NativeApi.InternalWrapper</seealso> api.
    /// </summary>
    public class Program
    {
        internal static string ProgName { get => Path.GetFileName(Assembly.GetExecutingAssembly().Location); }

        static void Main(string[] args)
        {
            int blckSze = -1;
            string input = "", output = "", mode = "copy";

            if (args.Length < 2)
                Usage();

            input = args[0];
            output = args[1];

            if (args.Length >= 3)
                mode = args[2].ToLower();

            if (args.Length >= 4)
                if (!Int32.TryParse(args[3], out blckSze))
                    blckSze = -1; // Cannot parse

            if (!File.Exists(input))
                Usage($"Input file {input} doesn't exist, can't copy!", 1);

            if (input.Equals(output, StringComparison.InvariantCultureIgnoreCase))
                Usage($"Input file {input} equals output {output}", 2);

            switch (mode)
            {
                case "move":    File.Move(input, output, true); break;
                case "write":   GsWrite(input, output, blckSze); break;
                case "xcopy":   NativeWrapper.XCopy(input, output); break;
                case "copy":
                default:        File.Copy(input, output, true); break;
            }
        }

        internal static void Usage(string msg = "", int exitCode = 0)
        {
            if (!string.IsNullOrEmpty(msg))
                Console.Error.WriteLine(msg);
            Environment.ExitCode = exitCode;
            Console.Out.Write($"Usage: {ProgName} source destination [copy|write|move] blocksize\r\n");
            Environment.Exit(Environment.ExitCode);
        }

        internal static void GsWrite(string inFile, string outFile, int bs = 0)
        {                                            
            int cnt = -1;
            if (bs <= 0)
            {
                byte[] inBytes = File.ReadAllBytes(inFile);
                File.WriteAllBytes(outFile, inBytes);
                return;
            }

            long inFileLen = (new FileInfo(inFile)).Length;
            byte[] byteBuf = new byte[bs];
            using (FileStream inStr = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                using (FileStream outStr = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    if (inStr != null && outStr != null)
                    {
                        while (bs * ++cnt < inFileLen)
                        {
                            int bRead = inStr.Read(byteBuf, 0, bs);
                            if (bRead > 0)
                                outStr.Write(byteBuf, 0, bRead);
                        }

                        inStr.Close();
                        outStr.Flush();
                        outStr.Close();
                        Console.WriteLine($"{ProgName}\nread: \t{inFile}\nwrote: \t{outFile}\n" +
                            $"bytes: \t{inFileLen},\trw-ops:\t{cnt} * {bs} blocksize.");
                    }
                }
            }
        }

    }
}
