using AlgorandAuthentication;
using ICSharpCode.SharpZipLib.GZip;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Text;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();


builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(async builderContext =>
    {
        if (builderContext.Route.RouteId == "routeOpenApi")
        {
            builderContext.AddResponseTransform(async responseContext =>
            {
                try
                {
                    if (responseContext?.ProxyResponse == null) return;

                    var stream = await responseContext.ProxyResponse.Content.ReadAsStreamAsync();
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var data = ms.ToArray();
                    if (data.Length < 2) return;
                    var isGzip = false;
                    var body = "";
                    if (data[0] == 31 && data[1] == 139)
                    {
                        // gzip
                        var input = new GZipInputStream(new MemoryStream(data));
                        using var reader = new StreamReader(input);
                        body = await reader.ReadToEndAsync();
                        isGzip = true;
                    }
                    else
                    {
                        body = Encoding.UTF8.GetString(data);
                    }

                    if (!string.IsNullOrEmpty(builder.Configuration["app:rewriteHost"]))
                    {
                        body = body.Replace("localhost", builder.Configuration["app:rewriteHost"]);
                    }
                    if (!string.IsNullOrEmpty(builder.Configuration["app:rewritePath"]))
                    {
                        body = body.Replace(@"""/""", $@"""/{builder.Configuration["app:rewritePath"]}/""");
                    }
                    body = body.Replace(@"X-Algo-API-Token", @"Authorization");
                    body = body.Replace(@"Generated header parameter. This token can be generated using the Goal command line tool. Example value ='b7e384d0317b8050ce45900a94a1931e28540e1f69b2d242b424659c341b4697'", @"ARC-0014 Algorand authentication transaction");

                    body = body.Replace(@"api_key", @"SigTx");
                    var obj = JsonConvert.DeserializeObject<JObject>(body);
                    var pathId2Path = obj["paths"] as JObject;
                    if (pathId2Path != null)
                    {
                        foreach (var item in pathId2Path)
                        {
                            item.Value["security"] = JsonConvert.DeserializeObject<JArray>(@"[{""SigTx"": [ ]}]");
                        }
                    }

                    body = JsonConvert.SerializeObject(obj, Formatting.Indented);

                    var bytes = Encoding.UTF8.GetBytes(body);
                    // Change Content-Length to match the modified body, or remove it.
                    responseContext.HttpContext.Response.ContentLength = bytes.Length;
                    // Response headers are copied before transforms are invoked, update any needed headers on the HttpContext.Response.
                    if (isGzip)
                    {
                        var outStreamBytes = new MemoryStream();
                        var outStream = new GZipOutputStream(outStreamBytes);
                        outStream.Write(bytes);
                        outStream.Flush();
                        await responseContext.HttpContext.Response.Body.WriteAsync(outStreamBytes.ToArray());
                    }
                    else
                    {
                        await responseContext.HttpContext.Response.Body.WriteAsync(bytes);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                }
            });
        }
    })
    ;
builder.Services.AddResponseCompression();
// Add services to the container.
builder.Services.AddRazorPages();


builder.Services.AddSwaggerGen(

    c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo
        {
            Title = "Algod service API",
            Version = "v1",
            Description = File.ReadAllText("doc/readme.md")
        });
        c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
        {
            Description = "ARC-0014 Algorand authentication transaction",
            In = ParameterLocation.Header,
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
        });

        var xmlFile = $"doc/documentation.xml";
        var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        c.OperationFilter<Swashbuckle.AspNetCore.Filters.SecurityRequirementsOperationFilter>();
        c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
        c.IncludeXmlComments(xmlPath);

    }
    );

builder.Services
 .AddAuthentication(AlgorandAuthenticationHandler.ID)
 .AddAlgorand(o =>
 {
     o.CheckExpiration = true;
     o.AlgodServer = builder.Configuration["algod:server"];
     o.AlgodServerToken = builder.Configuration["algod:token"];
     o.AlgodServerHeader = builder.Configuration["algod:header"];
     o.Realm = builder.Configuration["algod:realm"];
     o.NetworkGenesisHash = builder.Configuration["algod:networkGenesisHash"];
 });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AlgorandAuthenticationHandler.ID, new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build());
});


var app = builder.Build();


app.UseStaticFiles();
//app.UseSwagger();
app.UseSwaggerUI();
app.UseRouting();
app.UseAuthorization();
app.UseAuthentication();
app.MapReverseProxy();
app.MapRazorPages();
app.MapControllers();
app.Run();
