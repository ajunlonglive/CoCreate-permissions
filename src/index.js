const { CRUD_PERMISSION } = require('./constant')
const url = require("url");

/**
 * 
 * 
  apikeys: {
 	[$key]: {
 		domains: [],
 		collection: {
 			[$collection]: ['create', 'read', 'update', 'delete']
 		},
 		roles: ['admin', ...]
 	}
  },
  
  roles: {
  	[$role]: {
  		collection: {
  			[$collection]: ['create', 'read', 'update', 'delete']
  		}
  	},
  }
 	
 }
 */

class CoCreatePermission {
	constructor() {
		this.permissions = new Map();
	}
	
	setPermission(apikey, permission) {
		this.permissions.set(apikey, permission)
	}
	
	hasPermission(key) {
		return this.permissions.has(key)
	}
	
	async getRolesByKey(key, organization_id, type, host, apiKey) {
		if (this.permissions.get(key)) {
			return this.permissions.get(key)
		} else {
			let permission = await this.getPermissionObject(key, organization_id, type, host, apiKey);
			this.permissions.set(key, permission)
			return permission
		}
	}
		
	//. overrride function
	async getPermissionObject(key, organization_id, type, host, apiKey) {
		return null;
	}

	async createPermissionObject(permission, roles) {
		roles.map(role =>  {
			for( const roleKey in role){
				if (!["_id", "type", "name", "organization_id"].includes(roleKey)) {
					if (!permission[roleKey]){
						permission[roleKey] = role[roleKey]
					} else {
						if (Array.isArray(role[roleKey])){
							for (let item of role[roleKey]){
								if (!permission[roleKey].includes(item))
									permission[roleKey].push(item)
							}
						}
						else if ( typeof role[roleKey] == 'object'){
							for (const [c] of Object.entries(role[roleKey])) {
								if (!permission[roleKey][c]) {
									permission[roleKey][c] = role[roleKey][c]
								} else {
									if ( typeof role[roleKey][c] == 'object'){
										permission[roleKey][c] = {...permission[roleKey][c], ...role[roleKey][c]}
									} else {
										permission[roleKey][c] = role[roleKey][c]
									}
								}
							}
						} else {
							permission[roleKey] = role[roleKey]
						}
					}
				}
			}
		})
		return permission;
	}
	
	async check(module, data, req, user_id) {
		let host = this.getHost(req.headers)
		let status = false
		if (user_id){
			status = await this.checkPermissionObject({
				id: user_id,
				type: 'user_id',
				module,
				host,
				...data
			})
		}
		if (!status) {
			status = await this.checkPermissionObject({
				id: data.apiKey,
				type: 'apikey',
				module,
				host,
				...data
			})
		}
		return status;
	}
	
	getHost(headers) {
		const origin =  headers['origin']
		let host = headers['x-forwarded-for'];
		if (origin && origin !== 'null') {
			host = url.parse(origin).hostname;
		}
		return host
	}
	
	async checkPermissionObject({id, type, apiKey, organization_id, host, module, action, collection, document_id, name}) {
		if (!id || !organization_id) return false;
		
		const permission = await this.getRolesByKey(id, organization_id, type || "apikey", host, apiKey)
		if (!permission) return false
		if (permission.admin == 'true') {
			return true;
		}
		
		if (permission.organization_id !== organization_id) {
			return false;
		}
		if (!permission.hosts || !this.checkValue(permission.hosts, host)) {
			return false;
		}

		let status
		if (["createDocument", "readDocument", "updateDocument", "deleteDocument", "readDocumentList"].includes(module)){
			status = this.checkCollection(permission['collections'], collection, module)
			if (status) {
				status = this.checkDocument(permission['documents'], document_id, module, name)
			}
		}
		else {
			if (!action){
				action = module
				module = "actions"
			}
			status = this.checkPlugin(permission['modules'], module, action)
		}
		return status;
	}
	
	checkCollection(collections, collection, module) {
		if (!collections || !collection) return false;
		if (collections['*'] !== undefined)
			return true;
		let collection_roles = collections[collection];
		if (collection_roles && collection_roles.length > 0) {
			let status = collection_roles.some(x => {
				if (CRUD_PERMISSION[x]) {
					return CRUD_PERMISSION[x].includes(module) || CRUD_PERMISSION[x].includes('*');
				} else {
					return x == module;
				}
			})
			return status;
		} else {
			return false;
		}
	}
	
	checkDocument(documents, id, module, name) {
		let status = true;
		if (!documents || !id || !name) return true
		
		if (documents && id && documents[id]) {
			const { permissions, fields } = documents[id]
			const action_type = this.__getActionType(module)
			
			if (name && fields[name]) {
				status = fields[name].includes(action_type)
			} else {
				status = permissions.includes(action_type)
			} 
		} 

		return status;
	}
	
	checkPlugin(modules, module, action) {
		if (!modules || !module) return false;
		if (modules['*'] !== undefined)
			return true;

		let selected_module = modules[module]
		if (selected_module && selected_module.length > 0) {
			let status = selected_module.some(x => x == action || x == '*')
			return status;
		}
		return false;
	}

	checkValue(items, value) {
		if (!items) return false;
		if (items.includes("*") || items.includes(value)) {
			return true;
		}
		return false;
	}
	
	__getActionType(action) {
		let action_type = action
		for (let key in CRUD_PERMISSION) {
			if (CRUD_PERMISSION[key].includes(action)) {
				action_type = key
				break;
			}
		}
		return action_type
	}
}

module.exports = CoCreatePermission
