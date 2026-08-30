using Microsoft.Extensions.Configuration;

var config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
    .AddJsonFile("appsettings.Development.json", optional: true, reloadOnChange: false)
    .Build();

var demoSection = config.GetSection("DemoApp");

Console.WriteLine("Demo settings loaded:");
Console.WriteLine($"Service name: {demoSection["ServiceName"]}");
Console.WriteLine($"Environment: {demoSection["Environment"]}");
Console.WriteLine($"Username: {demoSection["Username"]}");
Console.WriteLine($"Password: {demoSection["Password"]}");
Console.WriteLine($"API key: {demoSection["ApiKey"]}");
Console.WriteLine($"Connection string: {demoSection["ConnectionString"]}");
