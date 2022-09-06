using MyApi;

var builder = WebApplication.CreateBuilder(args);
builder.ConfigureMyServices();

var app = builder.Build();
app.ConfigureMyApp();

app.Run();
