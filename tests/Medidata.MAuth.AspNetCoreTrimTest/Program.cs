using Medidata.MAuth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<MAuthMiddlewareOptions>().BindConfiguration("MAuth");

var app = builder.Build();
app.MapGet("/", () => "Hello World!");
app.Run();
