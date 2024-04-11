using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

// Пространство имен, в котором находится программа
namespace IPLogAnalyzer
{
    // Класс, содержащий точку входа в программу
    class Program
    {
        // Метод Main, который выполняется при запуске программы
        static void Main(string[] args)
        {
            // Проверка, переданы ли аргументы командной строки
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: IPLogAnalyzer --file-log [path] --file-output [path] [--address-start <address>] [--address-mask <mask>] --time-start <start_date> --time-end <end_date>");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            try
            {
                // Парсинг аргументов командной строки
                var arguments = ParseArguments(args);

                // Вывод информации о файлах и маске формата лога
                Console.WriteLine("Log File Path: " + arguments.FileLog);
                Console.WriteLine("Output File Path: " + arguments.FileOutput);
                if (!string.IsNullOrEmpty(arguments.AddressStart))
                    Console.WriteLine("Address Start: " + arguments.AddressStart);
                if (!string.IsNullOrEmpty(arguments.AddressMask))
                    Console.WriteLine("Address Mask: " + arguments.AddressMask);
                Console.WriteLine("Time Start: " + arguments.TimeStart.ToString("dd.MM.yyyy"));
                Console.WriteLine("Time End: " + arguments.TimeEnd.ToString("dd.MM.yyyy"));

                // Загрузка данных из файла логов
                var logEntries = LoadLogEntries(arguments.FileLog);

                // Вывод содержимого файла лога в консоль
                Console.WriteLine("\nLog File Contents:");
                foreach (var entry in logEntries)
                {
                    Console.WriteLine($"{entry.IPAddress}:{entry.Timestamp}");
                }
                Console.WriteLine();

                // Фильтрация записей по времени
                logEntries = FilterByTime(logEntries, arguments.TimeStart, arguments.TimeEnd);

                // Фильтрация записей по IP-адресам
                logEntries = FilterByAddress(logEntries, arguments.AddressStart, arguments.AddressMask);

                // Вывод результатов фильтрации в консоль
                Console.WriteLine("Filtered Log Entries:");
                foreach (var entry in logEntries)
                {
                    Console.WriteLine($"{entry.IPAddress}: {entry.Timestamp}");
                }
                Console.WriteLine();

                // Подсчет количества обращений с каждого адреса
                var ipCounts = CountIPAddresses(logEntries);

                // Вывод результатов подсчета в консоль
                Console.WriteLine("IP Address Counts:");
                foreach (var pair in ipCounts)
                {
                    Console.WriteLine($"{pair.Key}: {pair.Value}");
                }
                Console.WriteLine();

                // Запись результатов в файл
                WriteResults(ipCounts, arguments.FileOutput);

                Console.WriteLine("Analysis complete.");
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        // Метод для парсинга аргументов командной строки
        static AnalysisArguments ParseArguments(string[] args)
        {
            var arguments = new AnalysisArguments();

            for (int i = 0; i < args.Length; i += 2)
            {
                switch (args[i])
                {
                    case "--file-log":
                        arguments.FileLog = args[i + 1];
                        break;
                    case "--file-output":
                        arguments.FileOutput = args[i + 1];
                        break;
                    case "--address-start":
                        arguments.AddressStart = args[i + 1];
                        break;
                    case "--address-mask":
                        arguments.AddressMask = args[i + 1];
                        break;
                    case "--time-start":
                        arguments.TimeStart = DateTime.ParseExact(args[i + 1], "dd.MM.yyyy", null);
                        break;
                    case "--time-end":
                        arguments.TimeEnd = DateTime.ParseExact(args[i + 1], "dd.MM.yyyy", null);
                        break;
                    default:
                        throw new ArgumentException($"Unknown argument: {args[i]}");
                }
            }

            if (string.IsNullOrEmpty(arguments.FileLog))
                throw new ArgumentException("File log path is missing.");
            if (string.IsNullOrEmpty(arguments.FileOutput))
                throw new ArgumentException("File output path is missing.");
            if (arguments.TimeStart == DateTime.MinValue)
                throw new ArgumentException("Start time is missing or invalid.");
            if (arguments.TimeEnd == DateTime.MinValue)
                throw new ArgumentException("End time is missing or invalid.");

            return arguments;
        }

        // Метод для загрузки записей из файла лога
        static List<LogEntry> LoadLogEntries(string filePath)
        {
            var logEntries = new List<LogEntry>();

            try
            {
                using (var reader = new StreamReader(filePath))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        // Разделение строки лога на IP-адрес и дату
                        var parts = line.Split(new[] { ':' }, 2);
                        if (parts.Length == 2)
                        {
                            logEntries.Add(new LogEntry
                            {
                                IPAddress = parts[0],
                                Timestamp = DateTime.Parse(parts[1])
                            });
                        }
                    }
                }
            }
            catch (IOException e)
            {
                throw new ArgumentException($"Error reading log file: {e.Message}");
            }

            return logEntries;
        }

        // Метод для фильтрации записей по времени
        static List<LogEntry> FilterByTime(List<LogEntry> logEntries, DateTime startTime, DateTime endTime)
        {
            return logEntries.Where(entry => entry.Timestamp.Date >= startTime && entry.Timestamp.Date <= endTime).ToList();
        }

        // Метод для фильтрации записей по IP-адресам
        static List<LogEntry> FilterByAddress(List<LogEntry> logEntries, string addressStart, string addressMask)
        {
            if (addressStart == null || addressMask == null)
                return logEntries;

            var start = IPAddressToLong(addressStart);
            var mask = IPAddressToLong(addressMask);

            return logEntries.Where(entry => (IPAddressToLong(entry.IPAddress) & mask) == start).ToList();
        }

        // Метод для подсчета количества обращений с каждого IP-адреса
        static Dictionary<string, int> CountIPAddresses(List<LogEntry> logEntries)
        {
            var ipCounts = new Dictionary<string, int>();

            foreach (var entry in logEntries)
            {
                if (ipCounts.ContainsKey(entry.IPAddress))
                    ipCounts[entry.IPAddress]++;
                else
                    ipCounts[entry.IPAddress] = 1;
            }

            return ipCounts;
        }

        // Метод для записи результатов в файл
        static void WriteResults(Dictionary<string, int> ipCounts, string outputPath)
        {
            try
            {
                using (var writer = new StreamWriter(outputPath))
                {
                    foreach (var pair in ipCounts)
                    {
                        writer.WriteLine($"{pair.Key}: {pair.Value}");
                    }
                }
            }
            catch (IOException e)
            {
                throw new ArgumentException($"Error writing output file: {e.Message}");
            }
        }

        // Метод для преобразования IP-адреса в целочисленное значение
        static long IPAddressToLong(string ipAddress)
        {
            var bytes = ipAddress.Split('.').Select(byte.Parse).ToArray();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }
    }

    // Класс для хранения аргументов анализа
    class AnalysisArguments
    {
        public string FileLog { get; set; }      // Путь к файлу лога
        public string FileOutput { get; set; }   // Путь к файлу результатов
        public string AddressStart { get; set; } // Начальный IP-адрес
        public string AddressMask { get; set; }  // Маска подсети
        public DateTime TimeStart { get; set; }  // Время начала анализа
        public DateTime TimeEnd { get; set; }    // Время окончания анализа
    }

    // Класс для представления записи в логе
    class LogEntry
    {
        public string IPAddress { get; set; }   // IP-адрес
        public DateTime Timestamp { get; set; } // Дата и время
    }
}
