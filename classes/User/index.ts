import RDK, { Data, Response } from '@retter/rdk';
import { nanoid } from 'nanoid';
import * as validator from 'validator';

const rdk = new RDK();

export async function authorizer(data: Data): Promise<Response> {
    let {
        identity,
        methodName,
        userId,
        instanceId
    } = data.context


    if (identity === "developer") {
        // developer is a special identity that can do anything
        return { statusCode: 200 };
    }


    if (identity === "User" && userId === "STATIC") {
        // A STATIC method is calling another method here.
        if (methodName === "validatePassword" || methodName === "INIT")
            return {
                statusCode: 200
            }
        else 
            return {
                statusCode: 403,
            }
    }


    switch (methodName) {
        case "register":
        case "login": {
            if (identity === "anonymous" || identity === "none") {
                return { statusCode: 200 };
            } else {
                return { statusCode: 403 };
            }
        }
        case "updateProfile": {
            if (identity === "User" && instanceId === userId) {
                return { statusCode: 200 };
            } else {
                return { statusCode: 403 };
            }
        }
    }


    return { statusCode: 401 };
}

// export async function getInstanceId(): Promise<string> {
//     return Math.round(Math.random() * 10 ** 12).toString()
// }

// export async function getInstanceId(data: Data): Promise<string> {
//     const name = data.request.body.name;
//     let id: string = '';

//     if (name) {
//         id += name + '-';
//     }
//     const randomNumber = Math.floor(1000000000 + Math.random() * 9000000000).toString();
//     id += randomNumber;

//     return id;
// }

export async function getInstanceId(data: Data): Promise<string> {
    return data.request.body.name;
}


export async function init(data: Data<RegisterInput>): Promise<Data> {
    data.state.private = data.request.body
    data.response = {
        statusCode: 200,
        body: { userId: data.context.instanceId }
    }
    await rdk.setLookUpKey({ 
        key: { name: "email", value: data.request.body.email }
    })
    return data
}

export async function getState(data: Data): Promise<Response> {
    return {
        statusCode: 200,
        body: data.state,
        headers: { 'x-rio-state-version': data.version.toString() }
    };
}

export async function setState(data: Data): Promise<Data> {
    const { state, version } = data.request.body || {};
    if (data.version === version) {
        data.state = state;
        data.response = { statusCode: 204 };
    } else {
        data.response = {
            statusCode: 409,
            body: {
                message: `Your state version (${version}) is behind the current version (${data.version}).`,
            },
        }
    }
    return data;
}


export async function register(data: Data<RegisterInput>): Promise<Data>{
    const name = data.request.body.name;
    const email = data.request.body.email;
    const password = data.request.body.password;

    if (!validator.isEmail(email)) {
        data.response = { statusCode: 400, body: { message: "Invalid email format" } };
        return data;
    }

    let instance = await rdk.getInstance({
        classId: "User",
        lookupKey: {
            name: "email", value: email
        }
    });

    if (instance.statusCode === 200) {
        data.response = { statusCode: 400, body: { message: "User with this email already exists" } };
        return data;
    }

    if (password.length < 8) {
        data.response = { statusCode: 400, body: { message: "Password must be at least 8 characters long." } };
        return data;
    }

    // Proceed with user registration
    const getInstanceResponse = await rdk.getInstance({
        classId: "User",
        body: data.request.body
    });

    if (getInstanceResponse.statusCode !== 200) {
        data.response = { statusCode: 400, body: { message: "Cannot create user", addons: getInstanceResponse } };
        return data;
    }

    data.response = {
        statusCode: 200,
        body: "Registration OK",
    };
    return data;
}


export async function login(data: Data<LoginInput>): Promise<Data> {

    let result = await rdk.methodCall({
        classId: "User",
        lookupKey: {
            name: "email", value: data.request.body.email
        },
        methodName: "validatePassword",
        body: data.request.body
    })

    if(result.statusCode !== 200) {
        data.response = { statusCode: 401, body: { message: "Invalid email or password" } }
        return data
    }

    let tokenResult = await rdk.generateCustomToken({
        identity: "user",
        userId: result.body.userId
    })

    if(tokenResult.success !== true) {
        data.response = { statusCode: 500, body: { message: "Error generating token" } }
        return data
    }

    data.response = {
        statusCode: 200,
        body: tokenResult.data
    }
    return data
}

export async function validatePassword(data: Data<LoginInput>): Promise<Data> {
    const password = data.request.body.password;

    if (password !== data.state.private.password) {
        data.response = { statusCode: 401, body: { message: "Invalid password" } };
        return data;
    }

    data.response = {
        statusCode: 200,
        body: {
            userId: data.context.instanceId,
        }
    };

    return data;
}

export async function updateProfile(data: Data<UpdateProfileInput>): Promise<Data> {
    const { name, email, password} = data.request.body
    data.state.private.name = name ?? data.state.private.name
    data.state.private.email = email ?? data.state.private.email
    data.state.private.password = password ?? data.state.private.password
    if (password.length < 8) {
        data.response = { statusCode: 400, body: { message: "Password must be at least 8 characters long." } };
        return data;
    }
    data.response = {
        statusCode: 200,
        body: "OK"
    }
    return data
}
