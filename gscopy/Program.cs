using System.Reflection;
using Microsoft.Win32.Api;
using System.Runtime.Intrinsics.X86;

namespace gscopy
{
    /// <summary>
    /// gscopy simple console program,
    /// that demonstrates File.Copy, File.Move, Win32 Api kernel32.dll File.XCopy or File.Write
    /// <see cref="NativeWrapper.XCopy(string, string)">xcopy</see> switch uses 
    /// <seealso cref="https://github.com/heinrichelsigan/cmdcopy/blob/master/gscopy/InternalWrapper.cs">Win32.NativeApi.InternalWrapper</seealso> api.
    /// </summary>
    public class Program
    {
        private static int blckSze = -1;
        internal static string input = "", output = "", mode = "copy";

        internal static string ProgName { get => Assembly.GetExecutingAssembly().Location; }

        static void Main(string[] args)
        {
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
                Usage($"Input file {input} doesn't exist, can't copy!");

            if (input.Equals(output, StringComparison.InvariantCultureIgnoreCase))
                Usage($"Input file {input} equals output {output}");

            switch (mode)
            {
                case "move":    File.Move(input, output, true); break;
                case "write":   GsWrite(input, output, blckSze); break;
                case "xcopy":   NativeWrapper.XCopy(input, output); break;
                case "copy":
                default:        File.Copy(input, output, true); break;
            }
        }

        internal static void Usage(string msg = "")
        {
            if (!string.IsNullOrEmpty(input))
                Console.Error.WriteLine(msg);
            
            Console.Error.Write($"Usage: {ProgName} source destination [copy|write|move] blocksize\r\n");
            Environment.Exit(System.Environment.ExitCode);
        }

        internal static void GsWrite(string input, string output, int blocksize = 0)
        {                                            
            int cnt = -1;
            if (blocksize <= 0)
            {
                byte[] inBytes = File.ReadAllBytes(input);
                File.WriteAllBytes(output, inBytes);
                return;
            }

            long inFileLen = (new FileInfo(input)).Length;
            byte[] byteBuf = new byte[blocksize];
            using (FileStream inFs = new FileStream(input, FileMode.Open, FileAccess.Read))
            {
                using (FileStream outFs = new FileStream(output, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    if (inFs != null && outFs != null)
                    {
                        while (blocksize * ++cnt < inFileLen)
                        {
                            int bRead = inFs.Read(byteBuf, 0, blocksize);
                            if (bRead > 0)
                                outFs.Write(byteBuf, 0, bRead);
                        }

                        inFs.Close();
                        outFs.Flush();
                        outFs.Close();
                        Console.WriteLine($"{ProgName}\nread: \t{input}\nwrote: \t{output}\nbytes: \t{inFileLen},\trw-ops:\t{cnt} * {blocksize} blocksize.");
                    }
                }
            }
        }

    }
}
