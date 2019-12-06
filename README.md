[![Build](https://github.com/TankerHQ/identity-cs/workflows/Tests/badge.svg)](https://github.com/TankerHQ/identity-cs/actions)

# Identity

Identity generation using .Net for the [Tanker SDK](https://tanker.io/docs/latest).


## Installation

You can install it from [NuGet](https://www.nuget.org/packages/Tanker.Identity).

## Usage

```csharp

using System;

namespace App
{
    class Program
    {
        static void Main(string[] args)
        {
            var aliceIdentity = Tanker.Identity.CreateIdentity(@"<your app id>", @"<your app secret>", @"<some user Id>");
            Console.WriteLine(aliceIdentity);
            Console.ReadKey(true);
        }
    }
}

```


## Going further

Read more about *Identities* in the [Tanker guide](https://tanker.io/docs/latest/guide/adapting-server-code/).
