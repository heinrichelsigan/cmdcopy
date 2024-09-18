using System.Reflection;
using System.Runtime.Intrinsics.X86;

namespace gscopy
{
    /// <summary>
    /// gscopy simple console program, that can File.Copy, File.Move, Win32 Api kernel32.dll File.XCopy or File.Write
    /// <see cref="Win32.NativeApi.InternalWrapper.XCopy(string, string)">xcopy</see> switch uses 
    /// <seealso cref="https://github.com/heinrichelsigan/cmdcopy/blob/master/gscopy/InternalWrapper.cs">Win32.NativeApi.InternalWrapper</seealso> api.
    /// </summary>
    public class Program
    {        
        internal static string input = "";
        internal static string output = "";

        internal static string ProgName { get => Assembly.GetExecutingAssembly().Location; }

        static void Main(string[] args)
        {            
            int bs = -1;

            if (args.Length < 2)
                Usage();

            input = args[0];
            output = args[1];
          
            if (args.Length >= 4)
                if (!Int32.TryParse(args[3], out bs))
                    bs = -1; // Cannot parse

            if (!File.Exists(input))
                Usage($"Input file {input} doesn't exist, can't copy!");

            if (input.Equals(output, StringComparison.InvariantCultureIgnoreCase))
                Usage($"Input file {input} equals output {output}");

            if (args.Length >= 3)
                switch (args[2].ToLower())
                {
                    case "move":    File.Move(input, output, true); return;
                    case "write":   GsWrite(input, output, bs); return;
                    case "xcopy":   Win32.NativeApi.InternalWrapper.XCopy(input, output); return;
                    case "copy":
                    default:        break;
                }
            
            File.Copy (input, output, true);

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
            byte[] inBytes = File.ReadAllBytes(input);            
            int cnt = 0;
            
            if (blocksize <= 0)
            {
                File.WriteAllBytes(output, inBytes);
                return;
            }

            byte[] byteBuf = new byte[blocksize];
            FileStream inFs = new FileStream(input, FileMode.Open, FileAccess.Read);
            FileStream outFs = new FileStream(output, FileMode.OpenOrCreate, FileAccess.Write);
            if (inFs != null && outFs != null)
            {
                while (blocksize * cnt < inBytes.Length)
                {
                    int bRead = inFs.Read(byteBuf, 0, blocksize);
                    if (bRead > 0)
                        outFs.Write(byteBuf, 0, bRead);
                    cnt++;
                }

                inFs.Close();
                outFs.Flush();
                outFs.Close();
                Console.WriteLine($"{ProgName} read {input} wrote {output} {cnt} * {blocksize} times.");
            }

        }

    }
}
