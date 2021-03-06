<a href="#readme"><img src="https://tanker.io/images/github-logo.png" alt="Tanker logo" width="180" /></a>

[![Build](https://github.com/TankerHQ/identity-cs/workflows/Tests/badge.svg)](https://github.com/TankerHQ/identity-cs/actions)
[![Coverage](https://codecov.io/gh/TankerHQ/identity-cs/branch/master/graph/badge.svg)](https://codecov.io/gh/TankerHQ/identity-cs)

# Identity

Identity generation using .Net for the [Tanker SDK](https://docs.tanker.io/latest/).


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

Read more about *Identities* in the [Tanker documentation](https://docs.tanker.io/latest/api/identity/cs/).
